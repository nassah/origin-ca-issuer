package controllers

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	v1 "github.com/cloudflare/origin-ca-issuer/pkgs/apis/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
	"k8s.io/utils/clock"
	"sigs.k8s.io/controller-runtime/pkg/builder"
	"sigs.k8s.io/controller-runtime/pkg/envtest"
	logf "sigs.k8s.io/controller-runtime/pkg/log"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"
)

func TestOriginIssuerReconcileSuite(t *testing.T) {
	issuer := &v1.OriginIssuer{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "foo",
			Namespace: "default",
		},
		Spec: v1.OriginIssuerSpec{
			RequestType: v1.RequestTypeOriginRSA,
			Auth: v1.OriginIssuerAuthentication{
				ServiceKeyRef: &v1.SecretKeySelector{
					Name: "issuer-service-key",
					Key:  "key",
				},
			},
		},
	}
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "issuer-service-key",
			Namespace: "default",
		},
		StringData: map[string]string{
			"key": "v1.0-0x00BAB10C",
		},
	}

	if os.Getenv("KUBEBUILDER_ASSETS") == "" {
		t.Skip("kubebuilder environment was not setup")
	}

	cfg, err := envtestConfig(t)
	if err != nil {
		t.Fatalf("error starting envtest: %v", err)
	}

	mgr, err := manager.New(cfg, manager.Options{
		Metrics: metricsserver.Options{
			BindAddress: "0",
		},
		Scheme: scheme.Scheme,
	})
	if err != nil {
		t.Error(err)
	}
	c := mgr.GetClient()

	controller := &OriginIssuerController{
		Client: c,
		Reader: c,
		Clock:  clock.RealClock{},
		Log:    logf.Log,
	}

	builder.ControllerManagedBy(mgr).
		For(&v1.OriginIssuer{}).
		Complete(reconcile.AsReconciler(c, controller))

	cancel, errChan := StartTestManager(mgr, t)
	defer func() {
		cancel()
		if err := <-errChan; err != nil {
			t.Fatalf("error starting test manager: %v", err)
		}
	}()

	if err := c.Create(context.TODO(), secret); err != nil {
		t.Fatalf("error creating secret: %v", err)
	}
	defer c.Delete(context.TODO(), secret)

	if err := c.Create(context.TODO(), issuer); err != nil {
		t.Fatalf("error creating instance: %v", err)
	}
	defer c.Delete(context.TODO(), issuer)

	Eventually(t, func() bool {
		iss := v1.OriginIssuer{}
		namespacedName := types.NamespacedName{
			Namespace: issuer.Namespace,
			Name:      issuer.Name,
		}

		err := c.Get(context.TODO(), namespacedName, &iss)
		if err != nil {
			return false
		}

		return IssuerStatusHasCondition(iss.Status, v1.OriginIssuerCondition{Type: v1.ConditionReady, Status: v1.ConditionTrue})
	}, 5*time.Second, 10*time.Millisecond, "OriginIssuer reconciler")
}

func envtestConfig(t *testing.T) (*rest.Config, error) {
	t.Helper()

	env := &envtest.Environment{
		CRDDirectoryPaths: []string{filepath.Join("..", "..", "deploy", "crds")},
	}
	cmapi.AddToScheme(scheme.Scheme)
	v1.AddToScheme(scheme.Scheme)

	cfg, err := env.Start()
	if err != nil {
		return nil, err
	}

	t.Cleanup(func() {
		if err := env.Stop(); err != nil {
			t.Fatal(err)
		}
	})

	return cfg, nil
}

func StartTestManager(mgr manager.Manager, t *testing.T) (context.CancelFunc, chan error) {
	t.Helper()

	ctx, cancel := context.WithCancel(context.Background())

	errs := make(chan error, 1)

	go func() {
		errs <- mgr.Start(ctx)
	}()

	return cancel, errs
}

func Eventually(t *testing.T, condition func() bool, waitFor time.Duration, tick time.Duration, message string) bool {
	t.Helper()

	ch := make(chan bool, 1)

	timer := time.NewTimer(waitFor)
	defer timer.Stop()

	ticker := time.NewTicker(tick)
	defer ticker.Stop()

	for tick := ticker.C; ; {
		select {
		case <-timer.C:
			t.Fatalf("condition never satisfied: %s", message)
			return false
		case <-tick:
			tick = nil
			go func() { ch <- condition() }()
		case v := <-ch:
			if v {
				return true
			}
			tick = ticker.C
		}
	}
}
