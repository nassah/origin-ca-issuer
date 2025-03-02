package v1

import (
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

// +kubebuilder:object:root=true
// +kubebuilder:subresource:status

// An OriginIssuer represents the Cloudflare Origin CA as an external cert-manager issuer.
// It is scoped to a single namespace, so it can be used only by resources in the same
// namespace.
type OriginIssuer struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	// Desired state of the OriginIssuer resource
	Spec OriginIssuerSpec `json:"spec,omitempty"`

	// Status of the OriginIssuer. This is set and managed automatically.
	// +optional
	Status OriginIssuerStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// OriginIssuerList is a list of OriginIssuers.
type OriginIssuerList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata.omitempty"`

	Items []OriginIssuer `json:"items"`
}

// +kubebuilder:object:root=true
// +kubebuilder:resource:scope=Cluster
// +kubebuilder:subresource:status

// A ClusterOriginIssuer represents the Cloudflare Origin CA as an external cert-manager issuer.
// It is scoped to a single namespace, so it can be used only by resources in the same
// namespace.
type ClusterOriginIssuer struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`

	// Spec is the desired state of the ClusterOriginIssuer resource.
	Spec OriginIssuerSpec `json:"spec,omitempty"`

	// Status of the ClusterOriginIssuer. This is set and managed automatically.
	// +optional
	Status OriginIssuerStatus `json:"status,omitempty"`
}

// +kubebuilder:object:root=true

// ClusterOriginIssuerList is a list of OriginIssuers.
type ClusterOriginIssuerList struct {
	metav1.TypeMeta `json:",inline"`
	metav1.ListMeta `json:"metadata.omitempty"`

	Items []ClusterOriginIssuer `json:"items"`
}

// OriginIssuerSpec is the specification of an OriginIssuer. This includes any
// configuration required for the issuer.
type OriginIssuerSpec struct {
	// RequestType is the signature algorithm Cloudflare should use to sign the certificate.
	RequestType RequestType `json:"requestType"`

	// Auth configures how to authenticate with the Cloudflare API.
	Auth OriginIssuerAuthentication `json:"auth"`
}

// OriginIssuerStatus contains status information about an OriginIssuer
type OriginIssuerStatus struct {
	// List of status conditions to indicate the status of an OriginIssuer
	// Known condition types are `Ready`.
	// +optional
	Conditions []OriginIssuerCondition `json:"conditions,omitempty"`
}

// OriginIssuerAuthentication defines how to authenticate with the Cloudflare API.
// Only one of `serviceKeyRef` may be specified.
type OriginIssuerAuthentication struct {
	// ServiceKeyRef authenticates with an API Service Key.
	// +optional
	ServiceKeyRef *SecretKeySelector `json:"serviceKeyRef,omitempty"`

	// TokenRef authenticates with an API Token.
	// +optional
	TokenRef *SecretKeySelector `json:"tokenRef,omitempty"`
}

// SecretKeySelector contains a reference to a secret.
type SecretKeySelector struct {
	// Name of the secret in the issuer's namespace to select. If a cluster-scoped
	// issuer, the secret is selected from the "cluster resource namespace" configured
	// on the controller.
	Name string `json:"name"`
	// Key of the secret to select from. Must be a valid secret key.
	Key string `json:"key"`
}

// OriginIssuerCondition contains condition information for the OriginIssuer.
type OriginIssuerCondition struct {
	// Type of the condition, known values are ('Ready')
	Type ConditionType `json:"type"`

	// Status of the condition, one of ('True', 'False', 'Unknown')
	Status ConditionStatus `json:"status"`

	// LastTransitionTime is the timestamp corresponding to the last status
	// change of this condition.
	// +optional
	LastTransitionTime *metav1.Time `json:"lastTransitionTime,omitempty"`

	// Reason is a brief machine readable explanation for the condition's last
	// transition.
	// +optional
	Reason string `json:"reason,omitempty"`

	// Message is a human readable description of the details of the last
	// transition1, complementing reason.
	// +optional
	Message string `json:"message,omitempty"`
}

// +kubebuilder:validation:Enum=OriginRSA;OriginECC

// RequestType represents the signature algorithm used to sign certificates.
type RequestType string

const (
	// RequestTypeOriginRSA represents an RSA256 signature.
	RequestTypeOriginRSA RequestType = "OriginRSA"

	// RequestTypeOriginECC represents an ECDSA signature.
	RequestTypeOriginECC RequestType = "OriginECC"
)

// +kubebuilder:validation:Enum=Ready

// ConditionType represents an OriginIssuer condition value.
type ConditionType string

const (
	// ConditionReady represents that an OriginIssuer condition is in
	// a ready state and able to issue certificates.
	// If the `status` of this condition is `False`, CertificateRequest
	// controllers should prevent attempts to sign certificates.
	ConditionReady ConditionType = "Ready"
)

// +kubebuilder:validation:Enum=True;False;Unknown

// ConditionStatus represents a condition's status.
type ConditionStatus string

const (
	// ConditionTrue represents the fact that a given condition is true.
	ConditionTrue ConditionStatus = "True"

	// ConditionFalse represents the fact that a given condition is false.
	ConditionFalse ConditionStatus = "False"

	// ConditionUnknown represents the fact that a given condition is unknown.
	ConditionUnknown ConditionStatus = "Unknown"
)
