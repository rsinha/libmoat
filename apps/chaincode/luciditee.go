package main

import (
	"encoding/json"
	"github.com/hyperledger/fabric/core/chaincode/shim"
	pb "github.com/hyperledger/fabric/protos/peer"
)

type LuciditeeChaincode struct{}

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

var logger = shim.NewLogger("luciditee")

func (t *LuciditeeChaincode) Init(stub shim.ChaincodeStubInterface) pb.Response {
	Lr := LedgerResponse{Status:"Success", PolicyId:"", ComputeHistory:nil, ErrorMessage:"", OutputDelivery:nil}
	Resp, _ := json.Marshal(Lr)
	return shim.Success(Resp)
}

func (t* LuciditeeChaincode) failLedgerResponse(policyId, errorMessage string) []byte {
	Lr := LedgerResponse{Status:"Failure", PolicyId:policyId,
	ComputeHistory:nil, OutputDelivery:nil, ErrorMessage:errorMessage, Policy:""}
	Resp, _ := json.Marshal(Lr)
	return Resp
}

func (t *LuciditeeChaincode) createPolicy(stub shim.ChaincodeStubInterface, args []string) pb.Response {
	if len(args) < 2 {
		return shim.Success(t.failLedgerResponse("",
			"CreatePolicy must specify two inputs: <policy_id> <policy_data>"))
	}
	PolicyId := args[0]
	Policy := args[1]
	History := make([]string, 0)
	Outputs := make([]string, 0)
	if KnownPolicy, _ := stub.GetState(PolicyId); KnownPolicy == nil {
		LucidiTee_Policy := DataModel{PolicyId:PolicyId, Policy:Policy, ComputeHistory:History, OutputDelivery:Outputs}
		if dm, err := json.Marshal(&LucidiTee_Policy); err == nil {
			if err := stub.PutState(PolicyId, dm); err != nil {
				return shim.Success(t.failLedgerResponse(PolicyId, "Unable to write to ledger!"))
			}
		} else {
			return shim.Success(t.failLedgerResponse(PolicyId, "Unable to create policy; json marshalling error!"))
		}
	} else {
		return shim.Success(t.failLedgerResponse(PolicyId, "Policy with specified id already exist!"))
	}

	Lr := LedgerResponse{Status:"Success", PolicyId:PolicyId, ComputeHistory:History, ErrorMessage:"", OutputDelivery:Outputs}
	Resp, _ := json.Marshal(Lr)
	return shim.Success(Resp)
}

func (t *LuciditeeChaincode) recordCompute(stub shim.ChaincodeStubInterface, args []string) pb.Response {
	if len(args) < 2 {
		return shim.Success(t.failLedgerResponse("",
			"record_compute must specify two inputs:<Policy_Id>, <Compute_Record>!"))
	}

	PolicyId := args[0];
	ComputeRecord := args[1];

	var dm DataModel
	if KnownPolicy, _ := stub.GetState(PolicyId); KnownPolicy != nil {
		if err := json.Unmarshal(KnownPolicy, &dm); err != nil {
			return shim.Success(t.failLedgerResponse(PolicyId, "Unable to unmarshal the policy object!"))
		}
		// Append the compute_record to the history
		dm.ComputeHistory = append(dm.ComputeHistory, ComputeRecord)
		if UpdatePolicy, err := json.Marshal(&dm); err == nil {
			if err := stub.PutState(PolicyId, UpdatePolicy); err != nil {
				return shim.Success(t.failLedgerResponse(PolicyId, "Unable to perform record compute!"))
			}
		} else {
			return shim.Success(t.failLedgerResponse(PolicyId, "record_compute; json marshalling error!"))
		}

	} else {
		return shim.Success(t.failLedgerResponse(PolicyId, "Policy does not exists!"))
	}
	Lr := LedgerResponse{
		Status:"Success", PolicyId:PolicyId, ComputeHistory:dm.ComputeHistory,
		ErrorMessage:"", OutputDelivery:dm.OutputDelivery,
	}
	Resp, _ := json.Marshal(Lr)
	return shim.Success(Resp)
}

func (t *LuciditeeChaincode) queryPolicy(stub shim.ChaincodeStubInterface, args []string) pb.Response  {
	if len(args) < 1 {
		return shim.Success(t.failLedgerResponse("", "PolicyId must be specified!"))
	}
	PolicyId := args[0]
	var dm DataModel
	if KnownPolicy, _:= stub.GetState(PolicyId); KnownPolicy != nil {
		if err := json.Unmarshal(KnownPolicy, &dm); err != nil {
			return shim.Success(t.failLedgerResponse(PolicyId, "Unable to unmarshal the policy object!"))
		}
		Lr := LedgerResponse{
			Status:"Success", PolicyId:PolicyId, ComputeHistory:dm.ComputeHistory,
		    ErrorMessage:"", OutputDelivery:dm.OutputDelivery, Policy:dm.Policy,
		}
		Resp, _ := json.Marshal(Lr)
		return shim.Success(Resp)
	} else {
		return shim.Success(t.failLedgerResponse(PolicyId, "Policy does not exist!"))
	}
}

func (t *LuciditeeChaincode) deliverOutput(stub shim.ChaincodeStubInterface, args []string) pb.Response  {
	if len(args) < 2 {
		return shim.Success(t.failLedgerResponse("",
			"DeliverOutput must specify two inputs: policy_id and output_delivery_data"))
	}
	PolicyId := args[0]
	OutputDeliveryData := args[1];

	var dm DataModel
	if KnownPolicy, _ := stub.GetState(PolicyId); KnownPolicy != nil {
		if err := json.Unmarshal(KnownPolicy, &dm); err != nil {
			return shim.Success(t.failLedgerResponse(PolicyId, "Unable to unmarshal the policy object!"))
		}
		// Append the compute_record to the history
		dm.OutputDelivery = append(dm.OutputDelivery, OutputDeliveryData)
		if UpdatePolicy, err := json.Marshal(&dm); err == nil {
			if err := stub.PutState(PolicyId, UpdatePolicy); err != nil {
				return shim.Success(t.failLedgerResponse(PolicyId, "Unable to perform output delivery"))
			}
		} else {
			return shim.Success(t.failLedgerResponse(PolicyId, "OutputDelivery; json marshalling error!"))
		}

	} else {
		return shim.Success(t.failLedgerResponse(PolicyId, "Policy does not exists!"))
	}

	Lr := LedgerResponse{
		Status:"Success", PolicyId:PolicyId, ComputeHistory:dm.ComputeHistory,
		ErrorMessage:"", OutputDelivery:dm.OutputDelivery,
	}

	Resp, _ := json.Marshal(Lr)
	return shim.Success(Resp)
}

func (t *LuciditeeChaincode) Invoke(stub shim.ChaincodeStubInterface) pb.Response {
	function, args := stub.GetFunctionAndParameters()

	if function == "create_policy" {
		return t.createPolicy(stub, args)
	} else if function == "record_compute" {
		return t.recordCompute(stub, args)
	} else if function == "query_policy" {
		return t.queryPolicy(stub, args)
	} else if function == "deliver_output" {
		return t.deliverOutput(stub, args)
	} else {
		return shim.Error("Invalid invoke function name. Expecting \"invoke\"")
	}
}

func main() {
	err := shim.Start(new(LuciditeeChaincode))
	if err != nil {
		logger.Errorf("Error starting Test chaincode: %s", err)
	}
}