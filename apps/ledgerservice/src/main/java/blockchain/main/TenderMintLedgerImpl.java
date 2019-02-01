package blockchain.main;

import blockchain.service.ChaincodeService;
import com.google.protobuf.InvalidProtocolBufferException;
import com.google.protobuf.util.JsonFormat;
import com.sun.jersey.api.client.Client;
import com.sun.jersey.api.client.ClientResponse;
import com.sun.jersey.api.client.WebResource;
import io.grpc.Status;
import io.grpc.stub.StreamObserver;
import luciditee.LedgerServiceGrpc;
import luciditee.Ledgerentry;
import org.apache.commons.codec.binary.Hex;
import org.apache.commons.httpclient.HttpClient;
import org.json.JSONArray;
import org.json.JSONObject;

import java.util.ArrayList;
import java.util.Base64;
import java.util.List;

public class TenderMintLedgerImpl extends LedgerServiceGrpc.LedgerServiceImplBase {

    private static String tenderMintUrl = "http://localhost:26657/";

    private WebResource webResource = null;

    public TenderMintLedgerImpl() {
        Client client = Client.create();
        webResource = client.resource(tenderMintUrl);

    }

    private String createTenderMintObject(String method, String policyId, String payload){
        JSONObject entryObject = new JSONObject();
        entryObject.put("jsonrpc", "2.0");
        entryObject.put("id", "anything");
        entryObject.put("method", method);
        JSONObject params = new JSONObject();
        if(method.equals("abci_query")) {
            String policyPayload = Hex.encodeHexString(policyId.getBytes());
            params.put("data", policyPayload);
        } else {
            String policyPayload = Base64.getEncoder().encodeToString((policyId+"="+payload).getBytes());
            params.put("tx", policyPayload);
        }
        entryObject.put("params",params);
        return entryObject.toString();
    }

    private String postToTenderMint(String policyEntry) {

        ClientResponse response = webResource.accept("application/json").type("application/json")
                .post(ClientResponse.class,policyEntry);
        if (response.getStatus() != 200) {
            throw new RuntimeException("Failed : HTTP error code : "
                    + response.getStatus());
        }
        return response.getEntity(String.class);
    }

    private String sendToTenderMint(String method, String policyId, String payload) {


        if(method.equals("create")) {
            String policyEntry = createTenderMintObject("broadcast_tx_commit", policyId, payload);
            return postToTenderMint(policyEntry);
        } else if(method.equals("query")) {
            String policyQuery = createTenderMintObject("abci_query", policyId, "");
            return postToTenderMint(policyQuery);

        } else if(method.equals("status")) {
            Client client = Client.create();
            WebResource webResource =  client.resource(tenderMintUrl+"status");
            ClientResponse response = webResource.accept("application/json")
                    .get(ClientResponse.class);
            if (response.getStatus() != 200) {
                throw new RuntimeException("Failed : HTTP error code : "
                        + response.getStatus());
            }
            return response.getEntity(String.class);
        }
        return "";
    }

    private Ledgerentry.LedgerEntryResponse createLedgerEntry(long policyId, Ledgerentry.LedgerEntry policy, String ledgerFunc) {
        try {
//            String policyJson = JsonFormat.printer().print(policy);
            if(ledgerFunc.equals("create_policy")) {
                String policyByteStr = JsonFormat.printer().print(policy);
                JSONObject policyObject = new JSONObject();
                policyObject.put("policy", new JSONObject(policyByteStr));
                policyObject.put("history", new JSONArray());
                policyObject.put("output", new JSONArray());
                String result = sendToTenderMint("create", Long.toString(policyId), policyObject.toString());
//                System.out.println(result);
                return getCreatePolicyResponse(result);

            } else if(ledgerFunc.equals("record_compute")) {
                // query compute bucket
                String computeBucket = Long.toString(policyId);
                String queryResult = sendToTenderMint("query", computeBucket, "");
                JSONObject obj = new JSONObject(queryResult);
                String bucketExist = obj.getJSONObject("result").getJSONObject("response").getString("log");
                if(bucketExist.equals("exists")) {
                    String encodedHistory = obj.getJSONObject("result").getJSONObject("response").getString("value");
                    JSONObject policyObj = new JSONObject(new String(Base64.getDecoder().decode(encodedHistory)));
                    JSONArray computeHistory = policyObj.getJSONArray("history");
                    if(computeHistory.length() < 1) {
                        String policyByteStr = JsonFormat.printer().print(policy);
                        JSONObject policyObject = new JSONObject(policyByteStr);
                        JSONArray inputs = policyObject.getJSONObject("record").getJSONArray("inputs");
                        for(int i = 0; i < inputs.length(); i++) {
                            JSONObject o = inputs.getJSONObject(i);
                            o.put("digest", "");
                        }

                        JSONArray outputs = policyObject.getJSONObject("record").getJSONArray("outputs");
                        for(int i = 0; i < outputs.length(); i++) {
                            JSONObject o = outputs.getJSONObject(i);
                            o.put("digest", "");
                        }
                        JSONObject ch = new JSONObject();
                        ch.put("ch", policyObject.toString());
                        computeHistory.put(ch);

                        policyObj.put("history", computeHistory);
                        // Update Policy with compute history id
                        String entryResult = sendToTenderMint("create", computeBucket, policyObj.toString());
                        return getCreatePolicyResponse(entryResult);
                    } else {
                        return Ledgerentry.LedgerEntryResponse.newBuilder().setMessage("Success")
                                .setEntryId(policyId)
                                .setType(Ledgerentry.LedgerEntry.EntryType.CREATE).build();
                    }

                } else  {
                    // Unknown Policy
                }
            } else if(ledgerFunc.equals("deliver_output")) {
                // query compute bucket
                String computeBucket = Long.toString(policyId);
                String queryResult = sendToTenderMint("query", computeBucket, "");
                JSONObject obj = new JSONObject(queryResult);
                String bucketExist = obj.getJSONObject("result").getJSONObject("response").getString("log");
                if(bucketExist.equals("exists")) {
                    String encodedHistory = obj.getJSONObject("result").getJSONObject("response").getString("value");
                    JSONObject policyObj = new JSONObject(new String(Base64.getDecoder().decode(encodedHistory)));
                    JSONArray outputHistory = policyObj.getJSONArray("output");

                    if(outputHistory.length() < 1) {
                        String policyByteStr = JsonFormat.printer().print(policy);
                        JSONObject policyObject = new JSONObject(policyByteStr);
                        policyObject.getJSONObject("delivery").put("encrypted_key", "");
                        policyObject.getJSONObject("delivery").remove("encryptedKey");


                        JSONObject ch = new JSONObject();
                        ch.put("op", policyObject.toString());
                        outputHistory.put(ch);

                        policyObj.put("output", outputHistory);
                        // Update Policy with compute history id
                        String entryResult = sendToTenderMint("create", computeBucket, policyObj.toString());
                        return getCreatePolicyResponse(entryResult);
                    } else {
                        // Already added
                        return Ledgerentry.LedgerEntryResponse.newBuilder().setMessage("Success")
                                .setEntryId(policyId)
                                .setType(Ledgerentry.LedgerEntry.EntryType.CREATE).build();
                    }

                } else  {
                  // Unknown Policy
                }
            }

        } catch (Exception e) {
            e.printStackTrace();
        }
        return Ledgerentry.LedgerEntryResponse.newBuilder().setMessage("Failure").setType(Ledgerentry.LedgerEntry.EntryType.CREATE)
                .setEntryId(policyId).build();

    }

    private Ledgerentry.LedgerEntryResponse getCreatePolicyResponse(String result) {
        JSONObject obj = new JSONObject(result).getJSONObject("result");
        return Ledgerentry.LedgerEntryResponse.newBuilder().setMessage(obj.getString("hash"))
                .setEntryId(obj.getLong("height"))
                .setType(Ledgerentry.LedgerEntry.EntryType.CREATE).build();
    }

    @Override
    public void entry(Ledgerentry.LedgerEntry request, StreamObserver<Ledgerentry.LedgerEntryResponse> responseObserver) {

        Ledgerentry.LedgerEntry.EntryType entryType = request.getType();

        Ledgerentry.LedgerEntryResponse response = null;
        if(entryType == Ledgerentry.LedgerEntry.EntryType.CREATE) {
            response = createLedgerEntry(request.getSpec().getId(), request, "create_policy");
        } else if(entryType == Ledgerentry.LedgerEntry.EntryType.RECORD) {
            response = createLedgerEntry(request.getRecord().getId(), request, "record_compute");
        } else if (entryType == Ledgerentry.LedgerEntry.EntryType.DELIVER) {
            response = createLedgerEntry(request.getDelivery().getId(), request, "deliver_output");
        }
        // You must use a builder to construct a new Protobuffer object
        // Use responseObserver to send a single response back
        if(response != null) {
            responseObserver.onNext(response);
        } else {
            responseObserver.onNext(Ledgerentry.LedgerEntryResponse.newBuilder().setMessage("Failure").build());
        }
        // When you are done, you must call onCompleted.
        responseObserver.onCompleted();
//        responseObserver.onError(Status.ALREADY_EXISTS.asRuntimeException());

    }



    private List<Ledgerentry.LedgerEntry> getComputeHistory(JSONArray computeHistory) throws InvalidProtocolBufferException {
        List<Ledgerentry.LedgerEntry> ledgerEntries = new ArrayList<>();

        for(int i = 0; i < computeHistory.length(); i++) {
            String chs = computeHistory.getString(i);
            Ledgerentry.LedgerEntry.Builder chBuilder = Ledgerentry.LedgerEntry.newBuilder();
            JsonFormat.parser().merge(chs, chBuilder);
            ledgerEntries.add(chBuilder.build());
        }
        return ledgerEntries;
    }

    private List<Ledgerentry.LedgerEntry> getOutputDelivery(JSONArray outputDelivery) throws InvalidProtocolBufferException {
        List<Ledgerentry.LedgerEntry> ledgerEntries = new ArrayList<>();
        for(int i = 0; i < outputDelivery.length(); i++) {
            String ods = outputDelivery.getString(i);
            Ledgerentry.LedgerEntry.Builder outputDeliveryBuilder = Ledgerentry.LedgerEntry.newBuilder();
            JsonFormat.parser().merge(ods, outputDeliveryBuilder);
            ledgerEntries.add(outputDeliveryBuilder.build());
        }
        return ledgerEntries;
    }

    private Ledgerentry.LedgerQueryResponse queryLedger(Ledgerentry.LedgerQueryRequest request) {
        long policyId = request.getEntryId();
        Ledgerentry.LedgerEntry.EntryType entryType = request.getType();

        try {
            if(entryType == Ledgerentry.LedgerEntry.EntryType.CREATE) {
                List<Ledgerentry.LedgerEntry> ledgerEntries = new ArrayList<>();
                String result = sendToTenderMint("query", Long.toString(policyId), "");

                JSONObject obj = new JSONObject(result);
                String policyObject = obj.getJSONObject("result").getJSONObject("response").getString("value");

                JSONObject policy = new JSONObject(new String(Base64.getDecoder().decode(policyObject)));

                Ledgerentry.LedgerEntry.Builder policyBuilder = Ledgerentry.LedgerEntry.newBuilder();
                JsonFormat.parser().merge(policy.getJSONObject("policy").toString(), policyBuilder);
//                policyBuilder.mergeFrom(new String(Base64.getDecoder().decode(policyObject)).getBytes());
                ledgerEntries.add(policyBuilder.build());
                return Ledgerentry.LedgerQueryResponse.newBuilder().setEntryId(policyId).addAllEntries(ledgerEntries).build();

            } else if (entryType == Ledgerentry.LedgerEntry.EntryType.RECORD) {
                String result = sendToTenderMint("query", Long.toString(policyId), "");
                JSONObject obj = new JSONObject(result);

                String encodedHistory = obj.getJSONObject("result").getJSONObject("response").getString("value");
                JSONObject history = new JSONObject(new String(Base64.getDecoder().decode(encodedHistory)));
                JSONArray computeHistory = history.getJSONArray("history");

                if(computeHistory.length() > 0) {
                    String crObj  = computeHistory.getJSONObject(0).getString("ch");
                    JSONArray crObjHistory = new JSONArray();
                    crObjHistory.put(crObj);

                    return Ledgerentry.LedgerQueryResponse.newBuilder().setEntryId(policyId).addAllEntries(getComputeHistory(crObjHistory)).build();
                } else {

                }

            } else if(entryType == Ledgerentry.LedgerEntry.EntryType.DELIVER) {
                String result = sendToTenderMint("query", Long.toString(policyId), "");
                JSONObject obj = new JSONObject(result);

                String encodedHistory = obj.getJSONObject("result").getJSONObject("response").getString("value");
                JSONObject history = new JSONObject(new String(Base64.getDecoder().decode(encodedHistory)));
                JSONArray computeHistory = history.getJSONArray("output");

                if(computeHistory.length() > 0) {
                    String crObj  = computeHistory.getJSONObject(0).getString("op");
                    JSONArray crObjHistory = new JSONArray();
                    crObjHistory.put(crObj);

                    return Ledgerentry.LedgerQueryResponse.newBuilder().setEntryId(policyId).addAllEntries(getOutputDelivery(crObjHistory)).build();
                } else {

                }

            }

        } catch (Exception e) {
            e.printStackTrace();
        }
        return Ledgerentry.LedgerQueryResponse.newBuilder().setEntryId(policyId).build();
    }

    @Override
    public void query(Ledgerentry.LedgerQueryRequest request, StreamObserver<Ledgerentry.LedgerQueryResponse> queryResponseStreamObserver) {
        Ledgerentry.LedgerQueryResponse response = queryLedger(request);
        queryResponseStreamObserver.onNext(response);
        queryResponseStreamObserver.onCompleted();
//        queryResponseStreamObserver.onError(Status.ALREADY_EXISTS.asRuntimeException());
    }

    @Override
    public void info(Ledgerentry.BlockchainInfoRequest request, StreamObserver<Ledgerentry.BlockchainInfoResponse> blockchainInfoResponseStreamObserver) {
        String result = sendToTenderMint("status", "", "");
        JSONObject status = new JSONObject(result);
        String currentBlockHash = status.getJSONObject("result").getJSONObject("sync_info").getString("latest_block_hash");
        Long height = status.getJSONObject("result").getJSONObject("sync_info").getLong("latest_block_height");

        Ledgerentry.BlockchainInfoResponse response = Ledgerentry.BlockchainInfoResponse.newBuilder().setHeight(height)
                .setCurrentBlockHash(currentBlockHash)
                .setPreviousBlockHash("").build();

        blockchainInfoResponseStreamObserver.onNext(response);
        blockchainInfoResponseStreamObserver.onCompleted();
//        blockchainInfoResponseStreamObserver.onError(Status.ALREADY_EXISTS.asRuntimeException());
    }

}
