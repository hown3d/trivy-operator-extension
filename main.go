package main

import (
	"context"
	"flag"
	"fmt"
	"log"

	aquav1alpha1 "github.com/aquasecurity/trivy-operator/pkg/apis/aquasecurity/v1alpha1"
	"github.com/aquasecurity/trivy-operator/pkg/kube"
	"github.com/aquasecurity/trivy-operator/pkg/operator/etc"
	"github.com/aquasecurity/trivy-operator/pkg/operator/jobs"
	"github.com/aquasecurity/trivy-operator/pkg/plugins"
	"github.com/aquasecurity/trivy-operator/pkg/sbomreport"
	"github.com/aquasecurity/trivy-operator/pkg/trivyoperator"
	"github.com/aquasecurity/trivy-operator/pkg/vulnerabilityreport"
	vcontroller "github.com/aquasecurity/trivy-operator/pkg/vulnerabilityreport/controller"
	"github.com/bluele/gcache"
	"github.com/stackitcloud/trivy-operator-extension/controller"
	corev1 "k8s.io/api/core/v1"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/client-go/kubernetes"
	"k8s.io/klog/v2"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/cache"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	"sigs.k8s.io/controller-runtime/pkg/manager/signals"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"

	gardener_resources_v1alpha1 "github.com/gardener/gardener/pkg/apis/resources/v1alpha1"
)

const operatorNamespace = "kube-system"

var (
	namespace = flag.String("namespace", "", "namespace to limit the controller to, if empty all namespaces are watched")
	logger    = klog.NewKlogr()
)

func main() {
	flag.Parse()
	operatorConfig, err := etc.GetOperatorConfig()
	if err != nil {
		log.Fatal(err)
	}

	if err := run(operatorConfig); err != nil {
		log.Fatal(err)
	}
}

func run(operatorConfig etc.Config) error {
	// Set the default manager options.
	options := manager.Options{
		Scheme: trivyoperator.NewScheme(),
		Client: client.Options{
			Cache: &client.CacheOptions{
				DisableFor: []client.Object{
					&corev1.Secret{},
					&corev1.ServiceAccount{},
				},
			},
		},
		Metrics: metricsserver.Options{
			BindAddress: "0",
		},
	}

	ctrl.SetLogger(logger)

	if *namespace != "" {
		options.Cache.DefaultNamespaces = map[string]cache.Config{
			*namespace: {},
		}
	}

	kubeConfig, err := ctrl.GetConfig()
	if err != nil {
		return fmt.Errorf("getting kube client config: %w", err)
	}

	clientSet, err := kubernetes.NewForConfig(kubeConfig)
	if err != nil {
		return fmt.Errorf("constructing kube client: %w", err)
	}

	mgr, err := ctrl.NewManager(kubeConfig, options)
	if err != nil {
		return fmt.Errorf("constructing controllers manager: %w", err)
	}
	utilruntime.Must(gardener_resources_v1alpha1.AddToScheme(mgr.GetScheme()))
	utilruntime.Must(aquav1alpha1.AddToScheme(mgr.GetScheme()))

	configManager := trivyoperator.NewConfigManager(clientSet, "default")
	err = configManager.EnsureDefault(context.Background())
	if err != nil {
		return err
	}

	compatibleObjectMapper, err := kube.InitCompatibleMgr()
	if err != nil {
		return err
	}
	trivyOperatorConfig, err := configManager.Read(context.Background())
	if err != nil {
		return err
	}
	objectResolver := kube.NewObjectResolver(mgr.GetClient(), compatibleObjectMapper)
	if err != nil {
		return err
	}
	limitChecker := jobs.NewLimitChecker(operatorConfig, mgr.GetClient(), trivyOperatorConfig)
	secretsReader := kube.NewSecretsReader(mgr.GetClient())
	plugin, pluginContext, err := plugins.NewResolver().
		WithNamespace(operatorNamespace).
		WithServiceAccountName(operatorConfig.ServiceAccount).
		WithConfig(trivyOperatorConfig).
		WithClient(mgr.GetClient()).
		WithObjectResolver(&objectResolver).
		GetVulnerabilityPlugin()
	if err != nil {
		return err
	}
	err = plugin.Init(pluginContext)
	if err != nil {
		return err
	}

	wc := &vcontroller.WorkloadController{
		Logger:           ctrl.Log.WithName("reconciler").WithName("vulnerabilityreport"),
		Config:           operatorConfig,
		ConfigData:       trivyOperatorConfig,
		Client:           mgr.GetClient(),
		ObjectResolver:   objectResolver,
		LimitChecker:     limitChecker,
		SecretsReader:    secretsReader,
		Plugin:           plugin,
		PluginContext:    pluginContext,
		CacheSyncTimeout: *operatorConfig.ControllerCacheSyncTimeout,
		ServerHealthChecker: vcontroller.NewTrivyServerChecker(
			operatorConfig.TrivyServerHealthCheckCacheExpiration,
			gcache.New(1).LRU().Build(),
			vcontroller.NewHttpChecker()),
		VulnerabilityReadWriter: vulnerabilityreport.NewReadWriter(&objectResolver),
		SbomReadWriter:          sbomreport.NewReadWriter(&objectResolver),
		SubmitScanJobChan:       make(chan vcontroller.ScanJobRequest, operatorConfig.ConcurrentScanJobsLimit),
		ResultScanJobChan:       make(chan vcontroller.ScanJobResult, operatorConfig.ConcurrentScanJobsLimit),
	}

	mrc := controller.ManagedResourceController{
		Client: mgr.GetClient(),
		WC:     wc,
	}

	if err := mrc.SetupWithManager(mgr); err != nil {
		return err
	}

	if err := mgr.Start(signals.SetupSignalHandler()); err != nil {
		return fmt.Errorf("starting controllers manager: %w", err)
	}

	return nil
}
