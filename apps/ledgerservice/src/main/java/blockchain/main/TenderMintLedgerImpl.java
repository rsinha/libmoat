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
import org.apache.commons.httpclient.HttpClient;
import org.json.JSONArray;
import org.json.JSONObject;

import java.util.ArrayList;
import java.util.Base64;
import java.util.List;

public class TenderMintLedgerImpl extends LedgerServiceGrpc.LedgerServiceImplBase {

    private static String tenderMintUrl = "http://localhost:26657/";

    public TenderMintLedgerImpl() {

    }

    private String sendToTenderMint(String method, String policyId, String payload) {
        Client client = Client.create();
        WebResource webResource = null;
        if(method.equals("create")) {
            String encodedPayload = Base64.getEncoder().encodeToString(payload.getBytes());
            webResource = client.resource(tenderMintUrl+"broadcast_tx_commit?tx="+ "\""+ policyId+"="+encodedPayload + "\"");
        } else if(method.equals("query")) {
            webResource = client.resource(tenderMintUrl+"abci_query?data="+policyId);
        } else if(method.equals("status")) {
            webResource = client.resource(tenderMintUrl+"status");
        }
        if(webResource != null) {
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
            String policyJson = JsonFormat.printer().print(policy);
            if(ledgerFunc.equals("create_policy")) {
                String policyByteStr = new String(Base64.getEncoder().encode(policy.toByteArray()));
                String result = sendToTenderMint("create", Long.toString(policyId), policyByteStr);
                return getCreatePolicyResponse(result);
            } else if(ledgerFunc.equals("record_compute")) {
                // query compute bucket
                String queryResult = sendToTenderMint("query", "COMPUTE-"+Long.toString(policyId), "");
                JSONObject obj = new JSONObject(queryResult);
                String bucketExist = obj.getJSONObject("result").getJSONObject("response").getString("log");
                if(bucketExist.equals("exists")) {
                    String encodedHistory = obj.getJSONObject("result").getJSONObject("response").getString("value");
                    JSONObject history = new JSONObject(new String(Base64.getDecoder().decode(encodedHistory)));
                    JSONArray computeHistory = history.getJSONArray("history");
                    computeHistory.put(policyJson);
                    String entryResult = sendToTenderMint("create", "COMPUTE-"+Long.toString(policyId), history.toString());
                    return getCreatePolicyResponse(entryResult);

                } else  {
                    JSONArray computeHistory = new JSONArray();
                    computeHistory.put(policyJson);
                    JSONObject jsonObject = new JSONObject();
                    jsonObject.put("history", computeHistory);
                    String historyJson = jsonObject.toString();
                    String entryResult = sendToTenderMint("create", "COMPUTE-"+Long.toString(policyId), historyJson);
                    return getCreatePolicyResponse(entryResult);
                }
            } else if(ledgerFunc.equals("deliver_output")) {
                // query output bucket
                String queryResult = sendToTenderMint("query", "OUTPUT-"+Long.toString(policyId), "");
                JSONObject obj = new JSONObject(queryResult);
                String bucketExist = obj.getJSONObject("result").getJSONObject("response").getString("log");
                if(bucketExist.equals("exists")) {
                    String encodedHistory = obj.getJSONObject("result").getJSONObject("response").getString("value");
                    JSONObject history = new JSONObject(new String(Base64.getDecoder().decode(encodedHistory)));
                    JSONArray computeHistory = history.getJSONArray("output");
                    computeHistory.put(policyJson);
                    String entryResult = sendToTenderMint("create", "OUTPUT-"+Long.toString(policyId), history.toString());
                    return getCreatePolicyResponse(entryResult);

                } else  {
                    JSONArray computeHistory = new JSONArray();
                    computeHistory.put(policyJson);
                    JSONObject jsonObject = new JSONObject();
                    jsonObject.put("output", computeHistory);
                    String historyJson = jsonObject.toString();
                    String entryResult = sendToTenderMint("create", "OUTPUT-"+Long.toString(policyId), historyJson);
                    return getCreatePolicyResponse(entryResult);
                }
            }

        } catch (Exception e) {
            e.printStackTrace();
        }
        return Ledgerentry.LedgerEntryResponse.newBuilder().setMessage("Failure").setType(Ledgerentry.LedgerEntry.EntryType.CREATE)
                .setEntryId(policyId).build();

    }

    private Ledgerentry.LedgerEntryResponse getCreatePolicyResponse(String result) {
        JSONObject obj = new JSONObject(result);
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
        responseObserver.onError(Status.ALREADY_EXISTS.asRuntimeException());

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

                Ledgerentry.LedgerEntry.Builder policyBuilder = Ledgerentry.LedgerEntry.newBuilder();
                JsonFormat.parser().merge(new String(Base64.getDecoder().decode(policyObject)), policyBuilder);

                ledgerEntries.add(policyBuilder.build());
                return Ledgerentry.LedgerQueryResponse.newBuilder().setEntryId(policyId).addAllEntries(ledgerEntries).build();
            } else if (entryType == Ledgerentry.LedgerEntry.EntryType.RECORD) {
                String result = sendToTenderMint("query", "COMPUTE-"+Long.toString(policyId), "");
                JSONObject obj = new JSONObject(result);

                String encodedHistory = obj.getJSONObject("result").getJSONObject("response").getString("value");
                JSONObject history = new JSONObject(new String(Base64.getDecoder().decode(encodedHistory)));
                JSONArray computeHistory = history.getJSONArray("history");

                return Ledgerentry.LedgerQueryResponse.newBuilder().setEntryId(policyId).addAllEntries(getComputeHistory(computeHistory)).build();
            } else if(entryType == Ledgerentry.LedgerEntry.EntryType.DELIVER) {
                String result = sendToTenderMint("query", "OUTPUT-"+Long.toString(policyId), "");

                JSONObject obj = new JSONObject(result);

                String encodedHistory = obj.getJSONObject("result").getJSONObject("response").getString("value");
                JSONObject history = new JSONObject(new String(Base64.getDecoder().decode(encodedHistory)));
                JSONArray outputHistory = history.getJSONArray("output");
                return Ledgerentry.LedgerQueryResponse.newBuilder().setEntryId(policyId).addAllEntries(getOutputDelivery(outputHistory)).build();
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
        queryResponseStreamObserver.onError(Status.ALREADY_EXISTS.asRuntimeException());
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
        blockchainInfoResponseStreamObserver.onError(Status.ALREADY_EXISTS.asRuntimeException());
    }

}
