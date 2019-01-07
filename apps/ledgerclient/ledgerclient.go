package main

import (
	"crypto/sha256"
	"fmt"
	"golang.org/x/net/context"
	"google.golang.org/grpc"
	"ledgerclient/luciditee"
	"log"
	"os"
)


type DataModel struct {
	PolicyId string `json:"policy_id"`
	Policy string `json:"policy"`
	ComputeHistory []string `json:"compute_history"`
	OutputDelivery []string `json:"output_delivery"`
}

func main() {
	dest := "127.0.0.1:8080"
	//data, err := createSamplePolicy()



	//data, err := createSampleComputeRecord()

	//data, err := createOutputDelivery()

	//checkError(err)
	//data := createLedgerQuery()
	//sendQuery(data, dest)
	//sendDataToDest(data, dest)
	getBlockchainInfo(dest)
}

func createLedgerQuery() *luciditee.LedgerQueryRequest {
	lq := new(luciditee.LedgerQueryRequest)

	lq.Type = luciditee.LedgerEntry_DELIVER.Enum()
	PolicyId := uint64(46)
	lq.EntryId = &PolicyId
	return lq
}

func createSamplePolicy()(*luciditee.LedgerEntry,error ){
	le := new(luciditee.LedgerEntry)
	spec := sampleSpec()

	le.Type = luciditee.LedgerEntry_CREATE.Enum()
	le.Entry = &luciditee.LedgerEntry_Spec{spec}
	//data, err := proto.Marshal(le)
	//checkError(err)
	return le, nil
}

func sampleSpec() (*luciditee.Specification) {
	spec := new(luciditee.Specification)
	// policy id
	specId := uint64(46)
	spec.Id = &specId

	// policy inputs
	inputs := make([]*luciditee.Specification_InputDescription, 0)
	mintSpec := new(luciditee.Specification_InputDescription)
	mintSpec.Type = luciditee.Specification_KVS.Enum()
	mintInputId := string("mint_input")
	mintSpec.InputName = &mintInputId
	inputs = append(inputs, mintSpec)

	bankSpec := new(luciditee.Specification_InputDescription)
	bankSpec.Type = luciditee.Specification_FILE.Enum()
	bankInputId := string("bank_input")
	bankSpec.InputName = &bankInputId
	inputs = append(inputs, bankSpec)
	spec.Inputs = inputs

	// policy outputs
	outputs := make([]*luciditee.Specification_OutputDescription, 0)
	outSpec := new(luciditee.Specification_OutputDescription)
	outSpec.Type = luciditee.Specification_FILE.Enum()
	outEntityId := string("fin_output")
	outSpec.OutputName = &outEntityId
	outputs = append(outputs, outSpec)
	spec.Outputs = outputs

	// policy state descriptions
	stateDescriptions := make([]*luciditee.Specification_StateDescription, 0)
	stateDesc := new(luciditee.Specification_StateDescription)
	stateDesc.Type = luciditee.Specification_FILE.Enum()
	stateDescId := string("fin_state")
	stateDesc.StateName = &stateDescId
	stateDescriptions = append(stateDescriptions, stateDesc)

	spec.Statevars = stateDescriptions

	return spec
}

func createOutputDelivery()(*luciditee.LedgerEntry, error)  {
	le := new(luciditee.LedgerEntry)
	le.Type = luciditee.LedgerEntry_DELIVER.Enum()

	od := new(luciditee.Delivery)
	policyId := uint64(46)
	od.Id = &policyId

	// Blockchain height
	height := uint64(12)
	od.T = &height

	Key := []byte("ytettyeerterwtrtewrerw")
	od.EncryptedKey = Key

	le.Entry = &luciditee.LedgerEntry_Delivery{od}
	return le, nil
}

func createSampleComputeRecord() (*luciditee.LedgerEntry, error) {
	le := new(luciditee.LedgerEntry)
	le.Type = luciditee.LedgerEntry_RECORD.Enum()

	rec := new(luciditee.Record)
	// policy id
	recId := uint64(46)
	rec.Id = &recId

	// Blockchain height
	height := uint64(10)
	rec.T = &height

	recInputs := make([]*luciditee.Record_NamedDigest, 0)

	ri1 := new(luciditee.Record_NamedDigest)
	mintEntity := string("mint_input")
	ri1.Name = &mintEntity
	ri1.Digest = computeDigest(mintEntity)
	recInputs = append(recInputs, ri1)

	ri2 := new(luciditee.Record_NamedDigest)
	bankEntity := string("bank_input")
	ri2.Name = &bankEntity
	ri2.Digest = computeDigest(bankEntity)
	recInputs = append(recInputs, ri2)

	// input entity proof
	rec.Inputs = recInputs

	recOutputs := make([]*luciditee.Record_NamedDigest, 0)

	ro1 := new(luciditee.Record_NamedDigest)
	outputEntity := string("fin_output")
	ro1.Name = &outputEntity
	ro1.Digest = computeDigest(outputEntity)
	recOutputs = append(recOutputs, ro1)

	// out entity proof
	rec.Outputs = recOutputs

	stateVars := make([]*luciditee.Record_NamedDigest, 0)

	sv1 := new(luciditee.Record_NamedDigest)
	stateId := string("fin_state")
	sv1.Name = &stateId
	sv1.Digest = computeDigest(stateId)
	stateVars = append(stateVars, sv1)

	// state vars
	rec.Statevars = stateVars

	rec.Signatures = []byte("all signatures")

	le.Entry = &luciditee.LedgerEntry_Record{rec}

	//data, err := proto.Marshal(le)
	//checkError(err)
	return le, nil
}

func computeDigest(in string) []byte {
	h := sha256.New()
	h.Write([]byte(in))
	return h.Sum(nil)
}

func getBlockchainInfo(dst string) {
	conn, err := grpc.Dial(dst, grpc.WithInsecure())
	if err != nil {
		log.Fatalln("unable to connect to localhost")
	}
	defer conn.Close()

	client := luciditee.NewLedgerServiceClient(conn);

	ChainCodeId := string("luciditee")
	bir := luciditee.BlockchainInfoRequest{}
	bir.Chaincode = &ChainCodeId

	feature, err := client.Info(context.Background(), &bir)

	if err != nil {
		log.Fatalf("Failed to Send")
	}

	log.Println(feature)
	feature.Reset()
}

func sendQuery(query *luciditee.LedgerQueryRequest, dst string)  {
	conn, err := grpc.Dial(dst, grpc.WithInsecure())
	if err != nil {
		log.Fatalln("unable to connect to localhost")
	}
	defer conn.Close()

	client := luciditee.NewLedgerServiceClient(conn);

	feature, err := client.Query(context.Background(), query)

	if err != nil {
		log.Fatalf("Failed to Send")
	}

	log.Println(feature)
	feature.Reset()
}

func sendDataToDest(data *luciditee.LedgerEntry, dst string){
	conn, err := grpc.Dial(dst, grpc.WithInsecure())
	if err != nil {
		log.Fatalln("unable to connect to localhost")
	}
	defer conn.Close()

	client := luciditee.NewLedgerServiceClient(conn);

	feature, err := client.Entry(context.Background(), data)

	if err != nil {
		log.Fatalf("Failed to Send")
	}

	log.Println(feature)
	feature.Reset()
	

	//conn,err := net.Dial("tcp",dst)
	//checkError(err)
	//n,err := conn.Write(data)
	//checkError(err)
	//fmt.Println("Sent " + strconv.Itoa(n) + " bytes")
}

func checkError(err error){
	if err != nil {
		fmt.Fprintf(os.Stderr, "Fatal error: %s", err.Error())
		os.Exit(1)
	}
}
