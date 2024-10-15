package controller

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"reflect"
	"strings"

	"github.com/andybalholm/brotli"
	"github.com/aquasecurity/trivy-operator/pkg/apis/aquasecurity/v1alpha1"
	. "github.com/aquasecurity/trivy-operator/pkg/operator/predicate"
	vcontroller "github.com/aquasecurity/trivy-operator/pkg/vulnerabilityreport/controller"
	ctrl "sigs.k8s.io/controller-runtime"

	resourcesv1alpha1 "github.com/gardener/gardener/pkg/apis/resources/v1alpha1"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller"

	k8sapierror "k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/yaml"
	"k8s.io/utils/ptr"

	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"

	"sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
)

type ManagedResourceController struct {
	Client            client.Client
	SubmitScanJobChan chan vcontroller.ScanJobRequest
	ResultScanJobChan chan vcontroller.ScanJobResult
}

func (r *ManagedResourceController) SetupWithManager(mgr ctrl.Manager) error {
	err := ctrl.NewControllerManagedBy(mgr).WithOptions(controller.Options{
		// CacheSyncTimeout: r.CacheSyncTimeout,
	}).
		For(&resourcesv1alpha1.ManagedResource{}, builder.WithPredicates(
			Not(IsBeingTerminated),
		)).
		Owns(&v1alpha1.VulnerabilityReport{}).
		Owns(&v1alpha1.SbomReport{}).
		Complete(r.reconcileManagedResource())
	if err != nil {
		return err
	}
	return nil
}

func (r *ManagedResourceController) reconcileManagedResource() reconcile.Func {
	return func(ctx context.Context, req reconcile.Request) (reconcile.Result, error) {
		log := log.FromContext(ctx).WithValues("name", req.NamespacedName)

		mr := &resourcesv1alpha1.ManagedResource{}
		err := r.Client.Get(ctx, req.NamespacedName, mr)
		if err != nil {
			if k8sapierror.IsNotFound(err) {
				log.V(1).Info("Ignoring cached ManagedResource that must have been deleted")
				return ctrl.Result{}, nil
			}
			return ctrl.Result{}, fmt.Errorf("getting from cache: %w", err)
		}

		// only pickup managedresoureces meant for shoot
		class := ptr.Deref(mr.Spec.Class, "")
		if class != "" {
			log.Info("skipping since ManagedResource is not for shoot")
			return ctrl.Result{}, nil
		}

		// TODO: implement use of clustersbomreport cache.
		// Ref: https://github.com/aquasecurity/trivy-operator/blob/18e40db60a957cf233afeb442bddca62a03e45e9/pkg/vulnerabilityreport/controller/workload.go#L194-L203
		reusedReports := map[string]v1alpha1.SbomReportData{}

		var workloadErr error
		for _, secretRef := range mr.Spec.SecretRefs {
			secretName := types.NamespacedName{
				Namespace: mr.Namespace,
				Name:      secretRef.Name,
			}
			objs, err := r.getWorkloadFromSecret(ctx, secretName)
			if err != nil {
				workloadErr = errors.Join(workloadErr)
				continue
			}
			for _, workloadObj := range objs {
				log.V(1).Info("submitting workload", "workload", workloadObj)
				r.SubmitScanJobChan <- vcontroller.ScanJobRequest{Workload: workloadObj, Context: ctx, ClusterSbomReport: reusedReports}
			}
		}

		if workloadErr != nil {
			return ctrl.Result{}, workloadErr
		}

		// collect scan job processing results
		scanJobResult := <-r.ResultScanJobChan
		return scanJobResult.Result, scanJobResult.Error
		// return reconcile.Result{}, nil
	}
}

func (r *ManagedResourceController) getWorkloadFromSecret(ctx context.Context, name types.NamespacedName) ([]client.Object, error) {
	secret := new(corev1.Secret)
	err := r.Client.Get(ctx, name, secret)
	if err != nil {
		return nil, err
	}

	var decodeErrors error
	objs := make([]client.Object, 0, len(secret.Data))
	for key, data := range secret.Data {
		var reader io.Reader = bytes.NewReader(data)
		if strings.HasSuffix(key, resourcesv1alpha1.BrotliCompressionSuffix) {
			reader = brotli.NewReader(reader)
		}
		var (
			decoder    = yaml.NewYAMLOrJSONDecoder(reader, 1024)
			decodedObj map[string]any
		)
		for indexInFile := 0; true; indexInFile++ {
			err := decoder.Decode(&decodedObj)
			if err == io.EOF {
				break
			}
			if err != nil {
				decodeErrors = errors.Join(decodeErrors, err)
				continue
			}
			if decodedObj == nil {
				continue
			}

			obj := &unstructured.Unstructured{Object: decodedObj}
			typedObj, included, err := includeObject(obj)
			if err != nil {
				decodeErrors = errors.Join(decodeErrors, err)
				continue
			}
			if included {
				objs = append(objs, typedObj)
			}
		}

	}
	return objs, decodeErrors
}

// includeObject returns true for runtime.Object implementations that are known to have workload
func includeObject(u *unstructured.Unstructured) (client.Object, bool, error) {
	var (
		obj      client.Object
		err      error
		included bool = true
	)
	gvk := u.GroupVersionKind().String()
	switch gvk {
	case gvkFromObject(corev1.SchemeGroupVersion, new(corev1.Pod)).String():
		obj, err = convert[*corev1.Pod](u)
	case gvkFromObject(appsv1.SchemeGroupVersion, new(appsv1.Deployment)).String():
		obj, err = convert[*appsv1.Deployment](u)
	case gvkFromObject(appsv1.SchemeGroupVersion, new(appsv1.DaemonSet)).String():
		obj, err = convert[*appsv1.DaemonSet](u)
	case gvkFromObject(appsv1.SchemeGroupVersion, new(appsv1.ReplicaSet)).String():
		obj, err = convert[*appsv1.ReplicaSet](u)
	case gvkFromObject(appsv1.SchemeGroupVersion, new(appsv1.StatefulSet)).String():
		obj, err = convert[*appsv1.StatefulSet](u)
	case gvkFromObject(appsv1.SchemeGroupVersion, new(batchv1.Job)).String():
		obj, err = convert[*batchv1.Job](u)
	case gvkFromObject(appsv1.SchemeGroupVersion, new(batchv1.CronJob)).String():
		obj, err = convert[*batchv1.CronJob](u)
	}
	if obj == nil {
		included = false
	}
	return obj, included, err
}

func convert[T runtime.Object](u *unstructured.Unstructured) (T, error) {
	var empty T
	converter := runtime.DefaultUnstructuredConverter
	obj := new(T)
	err := converter.FromUnstructured(u.Object, obj)
	if err != nil {
		return empty, nil
	}
	return *obj, nil
}

func gvkFromObject(gv schema.GroupVersion, obj runtime.Object) schema.GroupVersionKind {
	t := reflect.TypeOf(obj)
	if t.Kind() != reflect.Pointer {
		panic("All types must be pointers to structs.")
	}
	t = t.Elem()
	return gv.WithKind(t.Name())
}
