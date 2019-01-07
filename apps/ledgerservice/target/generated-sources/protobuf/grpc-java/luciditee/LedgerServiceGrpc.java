package luciditee;

import static io.grpc.stub.ClientCalls.asyncUnaryCall;
import static io.grpc.stub.ClientCalls.asyncServerStreamingCall;
import static io.grpc.stub.ClientCalls.asyncClientStreamingCall;
import static io.grpc.stub.ClientCalls.asyncBidiStreamingCall;
import static io.grpc.stub.ClientCalls.blockingUnaryCall;
import static io.grpc.stub.ClientCalls.blockingServerStreamingCall;
import static io.grpc.stub.ClientCalls.futureUnaryCall;
import static io.grpc.MethodDescriptor.generateFullMethodName;
import static io.grpc.stub.ServerCalls.asyncUnaryCall;
import static io.grpc.stub.ServerCalls.asyncServerStreamingCall;
import static io.grpc.stub.ServerCalls.asyncClientStreamingCall;
import static io.grpc.stub.ServerCalls.asyncBidiStreamingCall;
import static io.grpc.stub.ServerCalls.asyncUnimplementedUnaryCall;
import static io.grpc.stub.ServerCalls.asyncUnimplementedStreamingCall;

/**
 */
@javax.annotation.Generated(
    value = "by gRPC proto compiler (version 1.7.0)",
    comments = "Source: ledgerentry.proto")
public final class LedgerServiceGrpc {

  private LedgerServiceGrpc() {}

  public static final String SERVICE_NAME = "luciditee.LedgerService";

  // Static method descriptors that strictly reflect the proto.
  @io.grpc.ExperimentalApi("https://github.com/grpc/grpc-java/issues/1901")
  public static final io.grpc.MethodDescriptor<luciditee.Ledgerentry.LedgerEntry,
      luciditee.Ledgerentry.LedgerEntryResponse> METHOD_ENTRY =
      io.grpc.MethodDescriptor.<luciditee.Ledgerentry.LedgerEntry, luciditee.Ledgerentry.LedgerEntryResponse>newBuilder()
          .setType(io.grpc.MethodDescriptor.MethodType.UNARY)
          .setFullMethodName(generateFullMethodName(
              "luciditee.LedgerService", "entry"))
          .setRequestMarshaller(io.grpc.protobuf.ProtoUtils.marshaller(
              luciditee.Ledgerentry.LedgerEntry.getDefaultInstance()))
          .setResponseMarshaller(io.grpc.protobuf.ProtoUtils.marshaller(
              luciditee.Ledgerentry.LedgerEntryResponse.getDefaultInstance()))
          .setSchemaDescriptor(new LedgerServiceMethodDescriptorSupplier("entry"))
          .build();
  @io.grpc.ExperimentalApi("https://github.com/grpc/grpc-java/issues/1901")
  public static final io.grpc.MethodDescriptor<luciditee.Ledgerentry.LedgerQueryRequest,
      luciditee.Ledgerentry.LedgerQueryResponse> METHOD_QUERY =
      io.grpc.MethodDescriptor.<luciditee.Ledgerentry.LedgerQueryRequest, luciditee.Ledgerentry.LedgerQueryResponse>newBuilder()
          .setType(io.grpc.MethodDescriptor.MethodType.UNARY)
          .setFullMethodName(generateFullMethodName(
              "luciditee.LedgerService", "query"))
          .setRequestMarshaller(io.grpc.protobuf.ProtoUtils.marshaller(
              luciditee.Ledgerentry.LedgerQueryRequest.getDefaultInstance()))
          .setResponseMarshaller(io.grpc.protobuf.ProtoUtils.marshaller(
              luciditee.Ledgerentry.LedgerQueryResponse.getDefaultInstance()))
          .setSchemaDescriptor(new LedgerServiceMethodDescriptorSupplier("query"))
          .build();
  @io.grpc.ExperimentalApi("https://github.com/grpc/grpc-java/issues/1901")
  public static final io.grpc.MethodDescriptor<luciditee.Ledgerentry.BlockchainInfoRequest,
      luciditee.Ledgerentry.BlockchainInfoResponse> METHOD_INFO =
      io.grpc.MethodDescriptor.<luciditee.Ledgerentry.BlockchainInfoRequest, luciditee.Ledgerentry.BlockchainInfoResponse>newBuilder()
          .setType(io.grpc.MethodDescriptor.MethodType.UNARY)
          .setFullMethodName(generateFullMethodName(
              "luciditee.LedgerService", "info"))
          .setRequestMarshaller(io.grpc.protobuf.ProtoUtils.marshaller(
              luciditee.Ledgerentry.BlockchainInfoRequest.getDefaultInstance()))
          .setResponseMarshaller(io.grpc.protobuf.ProtoUtils.marshaller(
              luciditee.Ledgerentry.BlockchainInfoResponse.getDefaultInstance()))
          .setSchemaDescriptor(new LedgerServiceMethodDescriptorSupplier("info"))
          .build();

  /**
   * Creates a new async stub that supports all call types for the service
   */
  public static LedgerServiceStub newStub(io.grpc.Channel channel) {
    return new LedgerServiceStub(channel);
  }

  /**
   * Creates a new blocking-style stub that supports unary and streaming output calls on the service
   */
  public static LedgerServiceBlockingStub newBlockingStub(
      io.grpc.Channel channel) {
    return new LedgerServiceBlockingStub(channel);
  }

  /**
   * Creates a new ListenableFuture-style stub that supports unary calls on the service
   */
  public static LedgerServiceFutureStub newFutureStub(
      io.grpc.Channel channel) {
    return new LedgerServiceFutureStub(channel);
  }

  /**
   */
  public static abstract class LedgerServiceImplBase implements io.grpc.BindableService {

    /**
     * <pre>
     * Define a RPC operation
     * </pre>
     */
    public void entry(luciditee.Ledgerentry.LedgerEntry request,
        io.grpc.stub.StreamObserver<luciditee.Ledgerentry.LedgerEntryResponse> responseObserver) {
      asyncUnimplementedUnaryCall(METHOD_ENTRY, responseObserver);
    }

    /**
     */
    public void query(luciditee.Ledgerentry.LedgerQueryRequest request,
        io.grpc.stub.StreamObserver<luciditee.Ledgerentry.LedgerQueryResponse> responseObserver) {
      asyncUnimplementedUnaryCall(METHOD_QUERY, responseObserver);
    }

    /**
     */
    public void info(luciditee.Ledgerentry.BlockchainInfoRequest request,
        io.grpc.stub.StreamObserver<luciditee.Ledgerentry.BlockchainInfoResponse> responseObserver) {
      asyncUnimplementedUnaryCall(METHOD_INFO, responseObserver);
    }

    @java.lang.Override public final io.grpc.ServerServiceDefinition bindService() {
      return io.grpc.ServerServiceDefinition.builder(getServiceDescriptor())
          .addMethod(
            METHOD_ENTRY,
            asyncUnaryCall(
              new MethodHandlers<
                luciditee.Ledgerentry.LedgerEntry,
                luciditee.Ledgerentry.LedgerEntryResponse>(
                  this, METHODID_ENTRY)))
          .addMethod(
            METHOD_QUERY,
            asyncUnaryCall(
              new MethodHandlers<
                luciditee.Ledgerentry.LedgerQueryRequest,
                luciditee.Ledgerentry.LedgerQueryResponse>(
                  this, METHODID_QUERY)))
          .addMethod(
            METHOD_INFO,
            asyncUnaryCall(
              new MethodHandlers<
                luciditee.Ledgerentry.BlockchainInfoRequest,
                luciditee.Ledgerentry.BlockchainInfoResponse>(
                  this, METHODID_INFO)))
          .build();
    }
  }

  /**
   */
  public static final class LedgerServiceStub extends io.grpc.stub.AbstractStub<LedgerServiceStub> {
    private LedgerServiceStub(io.grpc.Channel channel) {
      super(channel);
    }

    private LedgerServiceStub(io.grpc.Channel channel,
        io.grpc.CallOptions callOptions) {
      super(channel, callOptions);
    }

    @java.lang.Override
    protected LedgerServiceStub build(io.grpc.Channel channel,
        io.grpc.CallOptions callOptions) {
      return new LedgerServiceStub(channel, callOptions);
    }

    /**
     * <pre>
     * Define a RPC operation
     * </pre>
     */
    public void entry(luciditee.Ledgerentry.LedgerEntry request,
        io.grpc.stub.StreamObserver<luciditee.Ledgerentry.LedgerEntryResponse> responseObserver) {
      asyncUnaryCall(
          getChannel().newCall(METHOD_ENTRY, getCallOptions()), request, responseObserver);
    }

    /**
     */
    public void query(luciditee.Ledgerentry.LedgerQueryRequest request,
        io.grpc.stub.StreamObserver<luciditee.Ledgerentry.LedgerQueryResponse> responseObserver) {
      asyncUnaryCall(
          getChannel().newCall(METHOD_QUERY, getCallOptions()), request, responseObserver);
    }

    /**
     */
    public void info(luciditee.Ledgerentry.BlockchainInfoRequest request,
        io.grpc.stub.StreamObserver<luciditee.Ledgerentry.BlockchainInfoResponse> responseObserver) {
      asyncUnaryCall(
          getChannel().newCall(METHOD_INFO, getCallOptions()), request, responseObserver);
    }
  }

  /**
   */
  public static final class LedgerServiceBlockingStub extends io.grpc.stub.AbstractStub<LedgerServiceBlockingStub> {
    private LedgerServiceBlockingStub(io.grpc.Channel channel) {
      super(channel);
    }

    private LedgerServiceBlockingStub(io.grpc.Channel channel,
        io.grpc.CallOptions callOptions) {
      super(channel, callOptions);
    }

    @java.lang.Override
    protected LedgerServiceBlockingStub build(io.grpc.Channel channel,
        io.grpc.CallOptions callOptions) {
      return new LedgerServiceBlockingStub(channel, callOptions);
    }

    /**
     * <pre>
     * Define a RPC operation
     * </pre>
     */
    public luciditee.Ledgerentry.LedgerEntryResponse entry(luciditee.Ledgerentry.LedgerEntry request) {
      return blockingUnaryCall(
          getChannel(), METHOD_ENTRY, getCallOptions(), request);
    }

    /**
     */
    public luciditee.Ledgerentry.LedgerQueryResponse query(luciditee.Ledgerentry.LedgerQueryRequest request) {
      return blockingUnaryCall(
          getChannel(), METHOD_QUERY, getCallOptions(), request);
    }

    /**
     */
    public luciditee.Ledgerentry.BlockchainInfoResponse info(luciditee.Ledgerentry.BlockchainInfoRequest request) {
      return blockingUnaryCall(
          getChannel(), METHOD_INFO, getCallOptions(), request);
    }
  }

  /**
   */
  public static final class LedgerServiceFutureStub extends io.grpc.stub.AbstractStub<LedgerServiceFutureStub> {
    private LedgerServiceFutureStub(io.grpc.Channel channel) {
      super(channel);
    }

    private LedgerServiceFutureStub(io.grpc.Channel channel,
        io.grpc.CallOptions callOptions) {
      super(channel, callOptions);
    }

    @java.lang.Override
    protected LedgerServiceFutureStub build(io.grpc.Channel channel,
        io.grpc.CallOptions callOptions) {
      return new LedgerServiceFutureStub(channel, callOptions);
    }

    /**
     * <pre>
     * Define a RPC operation
     * </pre>
     */
    public com.google.common.util.concurrent.ListenableFuture<luciditee.Ledgerentry.LedgerEntryResponse> entry(
        luciditee.Ledgerentry.LedgerEntry request) {
      return futureUnaryCall(
          getChannel().newCall(METHOD_ENTRY, getCallOptions()), request);
    }

    /**
     */
    public com.google.common.util.concurrent.ListenableFuture<luciditee.Ledgerentry.LedgerQueryResponse> query(
        luciditee.Ledgerentry.LedgerQueryRequest request) {
      return futureUnaryCall(
          getChannel().newCall(METHOD_QUERY, getCallOptions()), request);
    }

    /**
     */
    public com.google.common.util.concurrent.ListenableFuture<luciditee.Ledgerentry.BlockchainInfoResponse> info(
        luciditee.Ledgerentry.BlockchainInfoRequest request) {
      return futureUnaryCall(
          getChannel().newCall(METHOD_INFO, getCallOptions()), request);
    }
  }

  private static final int METHODID_ENTRY = 0;
  private static final int METHODID_QUERY = 1;
  private static final int METHODID_INFO = 2;

  private static final class MethodHandlers<Req, Resp> implements
      io.grpc.stub.ServerCalls.UnaryMethod<Req, Resp>,
      io.grpc.stub.ServerCalls.ServerStreamingMethod<Req, Resp>,
      io.grpc.stub.ServerCalls.ClientStreamingMethod<Req, Resp>,
      io.grpc.stub.ServerCalls.BidiStreamingMethod<Req, Resp> {
    private final LedgerServiceImplBase serviceImpl;
    private final int methodId;

    MethodHandlers(LedgerServiceImplBase serviceImpl, int methodId) {
      this.serviceImpl = serviceImpl;
      this.methodId = methodId;
    }

    @java.lang.Override
    @java.lang.SuppressWarnings("unchecked")
    public void invoke(Req request, io.grpc.stub.StreamObserver<Resp> responseObserver) {
      switch (methodId) {
        case METHODID_ENTRY:
          serviceImpl.entry((luciditee.Ledgerentry.LedgerEntry) request,
              (io.grpc.stub.StreamObserver<luciditee.Ledgerentry.LedgerEntryResponse>) responseObserver);
          break;
        case METHODID_QUERY:
          serviceImpl.query((luciditee.Ledgerentry.LedgerQueryRequest) request,
              (io.grpc.stub.StreamObserver<luciditee.Ledgerentry.LedgerQueryResponse>) responseObserver);
          break;
        case METHODID_INFO:
          serviceImpl.info((luciditee.Ledgerentry.BlockchainInfoRequest) request,
              (io.grpc.stub.StreamObserver<luciditee.Ledgerentry.BlockchainInfoResponse>) responseObserver);
          break;
        default:
          throw new AssertionError();
      }
    }

    @java.lang.Override
    @java.lang.SuppressWarnings("unchecked")
    public io.grpc.stub.StreamObserver<Req> invoke(
        io.grpc.stub.StreamObserver<Resp> responseObserver) {
      switch (methodId) {
        default:
          throw new AssertionError();
      }
    }
  }

  private static abstract class LedgerServiceBaseDescriptorSupplier
      implements io.grpc.protobuf.ProtoFileDescriptorSupplier, io.grpc.protobuf.ProtoServiceDescriptorSupplier {
    LedgerServiceBaseDescriptorSupplier() {}

    @java.lang.Override
    public com.google.protobuf.Descriptors.FileDescriptor getFileDescriptor() {
      return luciditee.Ledgerentry.getDescriptor();
    }

    @java.lang.Override
    public com.google.protobuf.Descriptors.ServiceDescriptor getServiceDescriptor() {
      return getFileDescriptor().findServiceByName("LedgerService");
    }
  }

  private static final class LedgerServiceFileDescriptorSupplier
      extends LedgerServiceBaseDescriptorSupplier {
    LedgerServiceFileDescriptorSupplier() {}
  }

  private static final class LedgerServiceMethodDescriptorSupplier
      extends LedgerServiceBaseDescriptorSupplier
      implements io.grpc.protobuf.ProtoMethodDescriptorSupplier {
    private final String methodName;

    LedgerServiceMethodDescriptorSupplier(String methodName) {
      this.methodName = methodName;
    }

    @java.lang.Override
    public com.google.protobuf.Descriptors.MethodDescriptor getMethodDescriptor() {
      return getServiceDescriptor().findMethodByName(methodName);
    }
  }

  private static volatile io.grpc.ServiceDescriptor serviceDescriptor;

  public static io.grpc.ServiceDescriptor getServiceDescriptor() {
    io.grpc.ServiceDescriptor result = serviceDescriptor;
    if (result == null) {
      synchronized (LedgerServiceGrpc.class) {
        result = serviceDescriptor;
        if (result == null) {
          serviceDescriptor = result = io.grpc.ServiceDescriptor.newBuilder(SERVICE_NAME)
              .setSchemaDescriptor(new LedgerServiceFileDescriptorSupplier())
              .addMethod(METHOD_ENTRY)
              .addMethod(METHOD_QUERY)
              .addMethod(METHOD_INFO)
              .build();
        }
      }
    }
    return result;
  }
}
