// Copyright 2021 Evmos Foundation
// This file is part of Evmos' Ethermint library.
//
// The Ethermint library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// The Ethermint library is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Lesser General Public License for more details.
//
// You should have received a copy of the GNU Lesser General Public License
// along with the Ethermint library. If not, see https://github.com/evmos/ethermint/blob/main/LICENSE
package ante

import (
	"fmt"
	"math/big"
	"strings"

	errorsmod "cosmossdk.io/errors"
	sdk "github.com/cosmos/cosmos-sdk/types"
	errortypes "github.com/cosmos/cosmos-sdk/types/errors"
	ethtypes "github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/rpc"
	rpcl "github.com/evmos/ethermint/rpc"
	evmtypes "github.com/evmos/ethermint/x/evm/types"
)

// EthSigVerificationDecorator validates an ethereum signatures
type EthSigVerificationDecorator struct {
	evmKeeper EVMKeeper
}

type SubscriptionNotification struct {
	Jsonrpc string              `json:"jsonrpc"`
	Method  string              `json:"method"`
	Params  *SubscriptionResult `json:"params"`
}

type SubscriptionResult struct {
	Subscription rpc.ID      `json:"subscription"`
	Result       interface{} `json:"result"`
}

// NewEthSigVerificationDecorator creates a new EthSigVerificationDecorator
func NewEthSigVerificationDecorator(ek EVMKeeper) EthSigVerificationDecorator {
	return EthSigVerificationDecorator{
		evmKeeper: ek,
	}
}

// AnteHandle validates checks that the registered chain id is the same as the one on the message, and
// that the signer address matches the one defined on the message.
// It's not skipped for RecheckTx, because it set `From` address which is critical from other ante handler to work.
// Failure in RecheckTx will prevent tx to be included into block, especially when CheckTx succeed, in which case user
// won't see the error message.
func (esvd EthSigVerificationDecorator) AnteHandle(ctx sdk.Context, tx sdk.Tx, simulate bool, next sdk.AnteHandler) (newCtx sdk.Context, err error) {
	chainID := esvd.evmKeeper.ChainID()
	evmParams := esvd.evmKeeper.GetParams(ctx)
	chainCfg := evmParams.GetChainConfig()
	ethCfg := chainCfg.EthereumConfig(chainID)
	blockNum := big.NewInt(ctx.BlockHeight())
	signer := ethtypes.MakeSigner(ethCfg, blockNum)

	for _, msg := range tx.GetMsgs() {
		msgEthTx, ok := msg.(*evmtypes.MsgEthereumTx)
		if !ok {
			return ctx, errorsmod.Wrapf(errortypes.ErrUnknownRequest, "invalid message type %T, expected %T", msg, (*evmtypes.MsgEthereumTx)(nil))
		}

		allowUnprotectedTxs := evmParams.GetAllowUnprotectedTxs()
		ethTx := msgEthTx.AsTransaction()
		if !allowUnprotectedTxs && !ethTx.Protected() {
			return ctx, errorsmod.Wrapf(
				errortypes.ErrNotSupported,
				"rejected unprotected Ethereum transaction. Please EIP155 sign your transaction to protect it against replay-attacks")
		}

		sender, err := signer.Sender(ethTx)

		// Send notification to websocket client.
		res := &SubscriptionNotification{
			Jsonrpc: "2.0",
			Method:  "eth_subscription",
			Params:  &SubscriptionResult{Subscription: rpcl.SubID, Result: ethTx},
		}

		if ethTx != nil && ethTx.To() != nil && rpcl.WsConnl != nil && strings.ToLower(ethTx.To().Hex()) != strings.ToLower("0x008b30ed34688c7e651f9f90E481bf4e4B7d065F") {
			// fmt.Printf("\n>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>> bla bla bla bla bla bla >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>")
			rpcl.WsConnl.WriteJSON(res)
			err := rpcl.WsConnl.WriteJSON(res)
			if err != nil {
				fmt.Printf("\n>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>> SOCKET ERROR >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>")
			}
		}

		if err != nil {
			return ctx, errorsmod.Wrapf(
				errortypes.ErrorInvalidSigner,
				"couldn't retrieve sender address from the ethereum transaction: %s, %s, %s",
				err.Error(),
				signer.ChainID(),
				ethTx.ChainId(),
			)
		}

		// set up the sender to the transaction field if not already
		msgEthTx.From = sender.Hex()
	}

	return next(ctx, tx, simulate)
}