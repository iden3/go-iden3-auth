package transport

import (
	"context"
	"encoding/json"

	"github.com/iden3/go-schema-processor/v2/verifiable"
	"github.com/iden3/iden3comm/v2/protocol"
	"github.com/iden3/iden3comm/v2/transport/notification"
	"github.com/pkg/errors"
)

// SendPushAuthRequest sends authorization request to the user via a push notification.
func SendPushAuthRequest(
	ctx context.Context,
	diddoc verifiable.DIDDocument,
	authMsg protocol.AuthorizationRequestMessage,
) (*notification.UserNotificationResult, error) {
	authMsgBytes, err := json.Marshal(authMsg)
	if err != nil {
		return nil, errors.WithStack(err)
	}
	return notification.Notify(
		ctx,
		authMsgBytes,
		diddoc,
		nil,
	)
}

// SendPushContractInvokeRequest sends a contract invoke request to the user via a push notification.
func SendPushContractInvokeRequest(
	ctx context.Context,
	diddoc verifiable.DIDDocument,
	contractInvokeMsg protocol.ContractInvokeRequestMessage,
) (*notification.UserNotificationResult, error) {
	ciMsgBytes, err := json.Marshal(contractInvokeMsg)
	if err != nil {
		return nil, errors.WithStack(err)
	}
	return notification.Notify(
		ctx,
		ciMsgBytes,
		diddoc,
		nil,
	)
}
