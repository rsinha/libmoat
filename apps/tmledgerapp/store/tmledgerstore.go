package store

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"github.com/tendermint/tendermint/abci/example/code"
	"github.com/tendermint/tendermint/abci/types"
	cmn "github.com/tendermint/tendermint/libs/common"
	dbm "github.com/tendermint/tendermint/libs/db"
	"github.com/tendermint/tendermint/version"
)

var (
	stateKey        = []byte("stateKey")
	kvPairPrefixKey = []byte("kvPairKey:")

	ProtocolVersion version.Protocol = 0x1
)

type State struct {
	db      dbm.DB
	Size    int64  `json:"size"`
	Height  int64  `json:"height"`
	AppHash []byte `json:"app_hash"`
}

type DataModel struct {
	PolicyId string `json:"policy_id"`
	Policy string `json:"policy"`
	ComputeHistory []string `json:"compute_history"`
	OutputDelivery []string `json:"output_delivery"`
}

type LedgerResponse struct {
	Status string `json:"status"`
	Policy string `json:"policy"`
	PolicyId string `json:"policy_id"`
	ComputeHistory []string `json:"compute_history"`
	OutputDelivery [] string `json:"output_delivery"`
	ErrorMessage string `json:"error_message"`
}

func loadState(db dbm.DB) State {
	stateBytes := db.Get(stateKey)
	var state State
	if len(stateBytes) != 0 {
		err := json.Unmarshal(stateBytes, &state)
		if err != nil {
			panic(err)
		}
	}
	state.db = db
	return state
}

func saveState(state State) {
	stateBytes, err := json.Marshal(state)
	if err != nil {
		panic(err)
	}
	state.db.Set(stateKey, stateBytes)
}

func prefixKey(key []byte) []byte {
	return append(kvPairPrefixKey, key...)
}

//---------------------------------------------------

var _ types.Application = (*LucidiTEEApplication)(nil)

type LucidiTEEApplication struct {
	types.BaseApplication

	// validator set
	ValUpdates []types.ValidatorUpdate

	state State
}

func NewLucidiTEEApplication() *LucidiTEEApplication {
	state := loadState(dbm.NewMemDB())
	return &LucidiTEEApplication{state: state}
}

// Send Failed ledger response
func (app* LucidiTEEApplication) failLedgerResponse(policyId, errorMessage string) []byte {
	Lr := LedgerResponse{Status:"Failure", PolicyId:policyId,
		ComputeHistory:nil, OutputDelivery:nil, ErrorMessage:errorMessage, Policy:""}
	Resp, _ := json.Marshal(Lr)
	return Resp
}

// Track the block hash and header information
func (app *LucidiTEEApplication) BeginBlock(req types.RequestBeginBlock) types.ResponseBeginBlock {
	// reset valset changes
	app.ValUpdates = make([]types.ValidatorUpdate, 0)
	return types.ResponseBeginBlock{}
}

func (app *LucidiTEEApplication) Info(req types.RequestInfo) (resInfo types.ResponseInfo) {
	return types.ResponseInfo{
		Data:       fmt.Sprintf("{\"size\":%v}", app.state.Size),
		Version:    version.ABCIVersion,
		AppVersion: ProtocolVersion.Uint64(),
	}
}

func (app *LucidiTEEApplication) createPolicy(PolicyId, Policy string) types.ResponseDeliverTx  {
	History := make([]string, 0)
	Outputs := make([]string, 0)

	LucidiTee_Policy := DataModel{PolicyId:string(PolicyId), Policy:string(Policy),
		ComputeHistory:History, OutputDelivery:Outputs}

	if dm, err := json.Marshal(&LucidiTee_Policy); err == nil {
		app.state.db.Set(prefixKey([]byte(PolicyId)), dm)
		app.state.Size += 1

		tags := []cmn.KVPair{
			{Key: []byte("Success"), Value: []byte("")},
		}
		return types.ResponseDeliverTx{Code: code.CodeTypeOK, Tags: tags}
	} else {
		tags := []cmn.KVPair{
			{Key: []byte("error"), Value: []byte("Unable to create policy; json marshalling error!")},
		}
		return types.ResponseDeliverTx{Code: code.CodeTypeEncodingError, Tags: tags}
	}


}

func (app *LucidiTEEApplication) recordCompute(PolicyId, Data string) types.ResponseDeliverTx  {
	var dm DataModel

	if KnownPolicy := app.state.db.Get([]byte(PolicyId)); KnownPolicy != nil {
		if err := json.Unmarshal(KnownPolicy, &dm); err != nil {
			tags := []cmn.KVPair{
				{Key: []byte("error"), Value: []byte("Unable to unmarshal the policy object!")},
			}
			return types.ResponseDeliverTx{Code: code.CodeTypeEncodingError, Tags: tags}
		}
		// Append the compute_record to the history
		dm.ComputeHistory = append(dm.ComputeHistory, Data)
		if UpdatePolicy, err := json.Marshal(&dm); err == nil {
			app.state.db.Set([]byte(PolicyId), UpdatePolicy)
			app.state.Size += 1

			tags := []cmn.KVPair{
				{Key: []byte("Success"), Value: []byte("")},
			}
			return types.ResponseDeliverTx{Code: code.CodeTypeOK, Tags: tags}

		} else {
			tags := []cmn.KVPair{
				{Key: []byte("error"), Value: []byte("record_compute; json marshalling error!")},
			}
			return types.ResponseDeliverTx{Code: code.CodeTypeEncodingError, Tags: tags}
		}

	} else {
		tags := []cmn.KVPair{
			{Key: []byte("error"), Value: []byte("Policy Does Not Exist!")},
		}
		return types.ResponseDeliverTx{Code: code.CodeTypeEncodingError, Tags: tags}
	}
}

func (app *LucidiTEEApplication) deliverOutput(PolicyId, Data string) types.ResponseDeliverTx  {
	var dm DataModel

	if KnownPolicy := app.state.db.Get([]byte(PolicyId)); KnownPolicy != nil {
		if err := json.Unmarshal(KnownPolicy, &dm); err != nil {
			tags := []cmn.KVPair{
				{Key: []byte("error"), Value: []byte("Unable to unmarshal the policy object!")},
			}
			return types.ResponseDeliverTx{Code: code.CodeTypeEncodingError, Tags: tags}
		}

		dm.OutputDelivery = append(dm.OutputDelivery, Data)

		if UpdatePolicy, err := json.Marshal(&dm); err == nil {
			app.state.db.Set([]byte(PolicyId), UpdatePolicy)
			app.state.Size += 1

			tags := []cmn.KVPair{
				{Key: []byte("Success"), Value: []byte("")},
			}
			return types.ResponseDeliverTx{Code: code.CodeTypeOK, Tags: tags}

		} else {
			tags := []cmn.KVPair{
				{Key: []byte("error"), Value: []byte("record_compute; json marshalling error!")},
			}
			return types.ResponseDeliverTx{Code: code.CodeTypeEncodingError, Tags: tags}
		}

	} else {
		tags := []cmn.KVPair{
			{Key: []byte("error"), Value: []byte("Policy Does Not Exist!")},
		}
		return types.ResponseDeliverTx{Code: code.CodeTypeEncodingError, Tags: tags}
	}
}

// tx is either "key=value" or just arbitrary bytes
func (app *LucidiTEEApplication) DeliverTx(tx []byte) types.ResponseDeliverTx {
	//var key, value []byte
	parts := bytes.Split(tx, []byte("="))
	
	if len(parts) < 2 {
		tags := []cmn.KVPair{
			{Key: []byte("error"), Value: []byte("Create Policy must specify two inputs: <policy_id> and <policy_data>")},
		}
		return types.ResponseDeliverTx{Code: code.CodeTypeEncodingError, Tags: tags}
	}
	
	TxType := parts[0]
	TxData := parts[1]

	TxParts := bytes.Split(TxType, []byte(":"))
	Function := string(TxParts[0])
	PolicyId := string(TxParts[1])

	if Function == "create_policy" {
		return app.createPolicy(PolicyId, string(TxData))
	} else if Function == "record_compute" {
	    return app.recordCompute(PolicyId, string(TxData))
	} else if Function == "deliver_output" {
		return app.deliverOutput(PolicyId, string(TxData))
	} else {
		tags := []cmn.KVPair{
			{Key: []byte("error"), Value: []byte("Unknown method!")},
		}
		return types.ResponseDeliverTx{Code: code.CodeTypeEncodingError, Tags: tags}
	}
}

func (app *LucidiTEEApplication) CheckTx(tx []byte) types.ResponseCheckTx {
	return types.ResponseCheckTx{Code: code.CodeTypeOK, GasWanted: 1}
}

func (app *LucidiTEEApplication) Commit() types.ResponseCommit {
	// Using a memdb - just return the big endian size of the db
	appHash := make([]byte, 8)
	binary.PutVarint(appHash, app.state.Size)
	app.state.AppHash = appHash
	app.state.Height += 1
	saveState(app.state)
	return types.ResponseCommit{Data: appHash}
}

func (app *LucidiTEEApplication) Query(reqQuery types.RequestQuery) (resQuery types.ResponseQuery) {
	PolicyQuery := reqQuery.Data
	QueryParts := bytes.Split(PolicyQuery, []byte(":"))

	QueryType := string(QueryParts[0])
	PolicyId := QueryParts[1]

	var dm DataModel

	var resp types.ResponseQuery

	if Value := app.state.db.Get(prefixKey(PolicyId)); Value != nil {
		json.Unmarshal(Value, &dm)

		if QueryType == "CREATE" {
			resp.Value = []byte(dm.Policy)
		} else if QueryType == "COMPUTE" {
			Cnt := len(dm.ComputeHistory)
			if Cnt > 1 {
				resp.Value = []byte(dm.ComputeHistory[Cnt - 1])
			} else {
				resp.Value = []byte("")
			}
		} else if QueryType == "DELIVER" {
			Cnt := len(dm.OutputDelivery)
			if Cnt > 1 {
				resp.Value = []byte(dm.OutputDelivery[Cnt - 1])
			} else {
				resp.Value = []byte("")
			}
		}
	}
	return resp
}
