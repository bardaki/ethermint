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
package server

import (
	"context"
	"errors"
	"time"

	"github.com/cenkalti/backoff/v4"
	"github.com/cometbft/cometbft/libs/service"
	rpcclient "github.com/cometbft/cometbft/rpc/client"
	coretypes "github.com/cometbft/cometbft/rpc/core/types"
	"github.com/cometbft/cometbft/types"

	ethermint "github.com/evmos/ethermint/types"
)

const (
	ServiceName = "EVMIndexerService"

	NewBlockWaitTimeout = 60 * time.Second

	statusClientMaxRetryInterval = time.Second * 10
	statusClientTimeout          = time.Hour * 48
)

// EVMIndexerService indexes transactions for json-rpc service.
type EVMIndexerService struct {
	service.BaseService

	txIdxr ethermint.EVMTxIndexer
	client rpcclient.Client
}

// NewEVMIndexerService returns a new service instance.
func NewEVMIndexerService(
	txIdxr ethermint.EVMTxIndexer,
	client rpcclient.Client,
) *EVMIndexerService {
	is := &EVMIndexerService{txIdxr: txIdxr, client: client}
	is.BaseService = *service.NewBaseService(nil, ServiceName, is)
	return is
}

// OnStart implements service.Service by subscribing for new blocks
// and indexing them by events.
func (eis *EVMIndexerService) OnStart() error {
	ctx := context.Background()

	// when kava in state-sync mode, it returns zero as latest_block_height, which leads to undesired behavior, more
	// details here: https://github.com/Kava-Labs/ethermint/issues/79 to prevent this we wait until state-sync will finish
	exponentialBackOff := backoff.NewExponentialBackOff(
		backoff.WithMaxInterval(statusClientMaxRetryInterval), // set max retry interval
		backoff.WithMaxElapsedTime(statusClientTimeout),       // set timeout
	)
	if err := waitUntilClientReady(ctx, eis.client, exponentialBackOff); err != nil {
		return err
	}

	status, err := eis.client.Status(ctx)
	if err != nil {
		return err
	}
	latestBlock := status.SyncInfo.LatestBlockHeight
	newBlockSignal := make(chan struct{}, 1)

	// Use SubscribeUnbuffered here to ensure both subscriptions does not get
	// canceled due to not pulling messages fast enough. Cause this might
	// sometimes happen when there are no other subscribers.
	blockHeadersChan, err := eis.client.Subscribe(
		ctx,
		ServiceName,
		types.QueryForEvent(types.EventNewBlockHeader).String(),
		0)
	if err != nil {
		return err
	}

	go func() {
		for {
			msg := <-blockHeadersChan
			eventDataHeader := msg.Data.(types.EventDataNewBlockHeader)
			if eventDataHeader.Header.Height > latestBlock {
				latestBlock = eventDataHeader.Header.Height
				// notify
				select {
				case newBlockSignal <- struct{}{}:
				default:
				}
			}
		}
	}()

	lastBlock, err := eis.txIdxr.LastIndexedBlock()
	if err != nil {
		return err
	}
	if lastBlock == -1 {
		lastBlock = latestBlock
	}
	// blockErr indicates an error fetching an expected block or its results
	var blockErr error
	for {
		var block *coretypes.ResultBlock
		var blockResult *coretypes.ResultBlockResults
		if latestBlock <= lastBlock || blockErr != nil {
			// two cases:
			// 1. nothing to index (indexer is caught up). wait for signal of new block.
			// 2. previous attempt to index errored (failed to fetch the Block or BlockResults).
			//    in this case, wait before retrying the data fetching, rather than infinite looping
			//    a failing fetch. this can occur due to drive latency between the block existing and its
			//    block_results getting saved.
			select {
			case <-newBlockSignal:
			case <-time.After(NewBlockWaitTimeout):
			}
			continue
		}
		for i := lastBlock + 1; i <= latestBlock; i++ {
			block, blockErr = eis.client.Block(ctx, &i)
			if blockErr != nil {
				eis.Logger.Error("failed to fetch block", "height", i, "err", blockErr)
				break
			}
			blockResult, blockErr = eis.client.BlockResults(ctx, &i)
			if blockErr != nil {
				eis.Logger.Error("failed to fetch block result", "height", i, "err", blockErr)
				break
			}
			if err := eis.txIdxr.IndexBlock(block.Block, blockResult.TxsResults); err != nil {
				eis.Logger.Error("failed to index block", "height", i, "err", err)
			}
			lastBlock = blockResult.Height
		}
	}
}

// waitUntilClientReady waits until StatusClient is ready to serve requests
func waitUntilClientReady(ctx context.Context, client rpcclient.StatusClient, b backoff.BackOff) error {
	err := backoff.Retry(func() error {
		status, err := client.Status(ctx)
		if err != nil {
			return err
		}

		if status.SyncInfo.LatestBlockHeight == 0 {
			return errors.New("node isn't ready, possibly in state sync process")
		}

		return nil
	}, b)
	if err != nil {
		return err
	}

	return nil
}