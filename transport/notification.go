package transport

import (
	"context"
	"encoding/json"

	"github.com/iden3/go-schema-processor/verifiable"
	"github.com/iden3/iden3comm/protocol"
	"github.com/iden3/iden3comm/transport/notification"
	"github.com/pkg/errors"
)

func SendAuthRequest(
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

func SendContractInvokeRequest(
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
