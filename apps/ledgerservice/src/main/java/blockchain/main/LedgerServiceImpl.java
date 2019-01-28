package blockchain.main;

import blockchain.service.ChaincodeService;
import com.google.protobuf.InvalidProtocolBufferException;
import com.google.protobuf.util.JsonFormat;
import io.grpc.stub.StreamObserver;
import luciditee.LedgerServiceGrpc;
import luciditee.Ledgerentry.*;
import org.json.JSONArray;
import org.json.JSONObject;

import javax.json.Json;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;

public class LedgerServiceImpl extends LedgerServiceGrpc.LedgerServiceImplBase {
    private ChaincodeService chaincodeService;
    private static final String chaincodeName = "myChaincode";
    public LedgerServiceImpl(ChaincodeService chaincodeService) {
        this.chaincodeService = chaincodeService;
    }

    private LedgerEntryResponse createLedgerEntry(long policyId, LedgerEntry policy, String ledgerFunc) {
        try {
            String policyJson = JsonFormat.printer().print(policy);
//            String policyStr = policy.toString();
            String[] args = {Long.toString(policyId), policyJson};
//            String[] args = {Long.toString(policyId), policyStr};
            String result = chaincodeService.invokeChaincode(chaincodeName, ledgerFunc, args);
            return getCreatePolicyResponse(result);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return LedgerEntryResponse.newBuilder().setMessage("Failure").setType(LedgerEntry.EntryType.CREATE)
                .setEntryId(policyId).build();
    }

    private LedgerEntryResponse getCreatePolicyResponse(String result) {
        JSONObject obj = new JSONObject(result);
        return LedgerEntryResponse.newBuilder().setMessage(obj.getString("status"))
                .setEntryId(obj.getLong("policy_id"))
        .setType(LedgerEntry.EntryType.CREATE).build();
    }

    @Override
    public void entry(LedgerEntry request, StreamObserver<LedgerEntryResponse> responseObserver) {
        System.out.println(request);

        LedgerEntry.EntryType entryType = request.getType();

        LedgerEntryResponse response = null;
        if(entryType == LedgerEntry.EntryType.CREATE) {
            response = createLedgerEntry(request.getSpec().getId(), request, "create_policy");
        } else if(entryType == LedgerEntry.EntryType.RECORD) {
            response = createLedgerEntry(request.getRecord().getId(), request, "record_compute");
        } else if (entryType == LedgerEntry.EntryType.DELIVER) {
            response = createLedgerEntry(request.getDelivery().getId(), request, "deliver_output");
        }
        // You must use a builder to construct a new Protobuffer object
        // Use responseObserver to send a single response back
        if(response != null) {
            responseObserver.onNext(response);
        } else {
            responseObserver.onNext(LedgerEntryResponse.newBuilder().setMessage("Failure").build());
        }
        // When you are done, you must call onCompleted.
        responseObserver.onCompleted();
    }

    private List<LedgerEntry> getComputeHistory(JSONArray computeHistory) throws InvalidProtocolBufferException {
        List<LedgerEntry> ledgerEntries = new ArrayList<>();

        for(int i = 0; i < computeHistory.length(); i++) {
            String chs = computeHistory.getString(i);
            LedgerEntry.Builder chBuilder = LedgerEntry.newBuilder();
            JsonFormat.parser().merge(chs, chBuilder);
            ledgerEntries.add(chBuilder.build());
        }
        return ledgerEntries;
    }

    private List<LedgerEntry> getOutputDelivery(JSONArray outputDelivery) throws InvalidProtocolBufferException {
        List<LedgerEntry> ledgerEntries = new ArrayList<>();
        for(int i = 0; i < outputDelivery.length(); i++) {
            String ods = outputDelivery.getString(i);
            LedgerEntry.Builder outputDeliveryBuilder = LedgerEntry.newBuilder();
            JsonFormat.parser().merge(ods, outputDeliveryBuilder);
            ledgerEntries.add(outputDeliveryBuilder.build());
        }
        return ledgerEntries;
    }

    private LedgerQueryResponse filterResponseByType(JSONObject obj, LedgerEntry.EntryType entryType) {
        String status = obj.getString("status");
        if(status.equals("Failure")) {
            return LedgerQueryResponse.newBuilder().setEntryId(obj.getLong("policy_id")).build();
        }

        try {
            long policyId = obj.getLong("policy_id");
            if(entryType == LedgerEntry.EntryType.CREATE) {
                List<LedgerEntry> ledgerEntries = new ArrayList<>();
                String policyObject = obj.getString("policy");
//                JSONArray computeHistory = obj.getJSONArray("compute_history");
//                JSONArray outputDelivery = obj.getJSONArray("output_delivery");

                LedgerEntry.Builder policyBuilder = LedgerEntry.newBuilder();
                JsonFormat.parser().merge(policyObject, policyBuilder);
                ledgerEntries.add(policyBuilder.build());

//                ledgerEntries.addAll(getComputeHistory(computeHistory));
//                ledgerEntries.addAll(getOutputDelivery(outputDelivery));

                return LedgerQueryResponse.newBuilder().setEntryId(policyId).addAllEntries(ledgerEntries).build();
            } else if(entryType == LedgerEntry.EntryType.RECORD) {
                List<LedgerEntry> ledgerEntries = new ArrayList<>();
                JSONArray computeHistory = obj.getJSONArray("compute_history");
                ledgerEntries.addAll(getComputeHistory(computeHistory));
                return LedgerQueryResponse.newBuilder().setEntryId(policyId).addAllEntries(ledgerEntries).build();
            } else if(entryType == LedgerEntry.EntryType.DELIVER) {
                List<LedgerEntry> ledgerEntries = new ArrayList<>();
                JSONArray computeHistory = obj.getJSONArray("output_delivery");
                ledgerEntries.addAll(getOutputDelivery(computeHistory));
                return LedgerQueryResponse.newBuilder().setEntryId(policyId).addAllEntries(ledgerEntries).build();
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
        return LedgerQueryResponse.newBuilder().setEntryId(obj.getLong("policy_id")).build();
    }

    private LedgerQueryResponse queryLedger(LedgerQueryRequest request) {
        long policyId = request.getEntryId();
        LedgerEntry.EntryType entryType = request.getType();

        String queryType = "CREATE";
        if(entryType == LedgerEntry.EntryType.CREATE) {
            queryType = "CREATE";

        } else if (entryType == LedgerEntry.EntryType.RECORD) {
            queryType = "COMPUTE";

        } else if(entryType == LedgerEntry.EntryType.DELIVER) {
            queryType = "DELIVER";

        }
        String[] args = {Long.toString(policyId), queryType};
        String result = chaincodeService.queryChaincode(chaincodeName, "query_policy", args);

        try {
            JSONObject obj = new JSONObject(result);
            return filterResponseByType(obj, entryType);
        } catch (Exception e) {
            e.printStackTrace();
        }

      return LedgerQueryResponse.newBuilder().setEntryId(policyId).build();
    }

    @Override
    public void query(LedgerQueryRequest request, StreamObserver<LedgerQueryResponse> queryResponseStreamObserver) {
        System.out.println(request);
        LedgerQueryResponse response = queryLedger(request);
        queryResponseStreamObserver.onNext(response);
        queryResponseStreamObserver.onCompleted();
    }

    @Override
    public void info(BlockchainInfoRequest request, StreamObserver<BlockchainInfoResponse> blockchainInfoResponseStreamObserver) {
        BlockchainInfoResponse response = chaincodeService.bcInfo();
        blockchainInfoResponseStreamObserver.onNext(response);
        blockchainInfoResponseStreamObserver.onCompleted();
    }
}