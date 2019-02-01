package main

import (
	"github.com/tendermint/abci/server"
	"github.com/tendermint/abci/example/tmledgerapp/store"

	cmn "github.com/tendermint/tmlibs/common"
)

func main() {
	initTmLedger()
}

func initTmLedger() error {
	//logger := log.NewTMLogger(log.NewSyncWriter(os.Stdout))

	// Create the application
	//var app types.Application


	LedgerApp := store.NewLucidiTEEApplication()

	// Start the listener
	srv, err := server.NewServer("tcp://0.0.0.0:46658", "socket", LedgerApp)
	if err != nil {
		return err
	}
	//srv.SetLogger(logger.With("module", "abci-server"))
	if err := srv.Start(); err != nil {
		return err
	}

	// Wait forever
	cmn.TrapSignal(func() {
		// Cleanup
		srv.Stop()
	})
	return nil
}