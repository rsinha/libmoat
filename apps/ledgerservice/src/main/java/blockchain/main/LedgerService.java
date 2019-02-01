package blockchain.main;

import blockchain.service.ChaincodeService;
import blockchain.service.ChaincodeServiceImpl;
import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.LoggerContext;
import io.grpc.Server;
import io.grpc.ServerBuilder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


public class LedgerService {
    private static final Logger logger = LoggerFactory.getLogger(LedgerService.class);



   static class LedgerInstance {
       private ChaincodeService chaincodeService;

       public LedgerInstance(ChaincodeService chaincode) {
           this.chaincodeService = chaincode;
       }

       public void bootStrapLedger() {
           try{
               // 1.Create Channel
               // 2.Install Chaincode
               // 3.Instantiate Chaincode
//               logger.info("Creating user.....");
               String result = chaincodeService.enrollAndRegister("test_lutiditee");
//               logger.info(result);

//               logger.info("Constructing channel.....");
               String channelResult = chaincodeService.constructChannel();
//               logger.info(channelResult);

//               logger.info("Installing ChainCode.......");
               String installationResult = chaincodeService.installChaincode("myChaincode");
               logger.info(installationResult);

//               logger.info("Instantiating ChainCode.......");
               String[] args = {};
               String instantiationResult = chaincodeService.instantiateChaincode("myChaincode", "init", args);
               logger.info(instantiationResult);
               System.out.println(installationResult);

           } catch (Exception e) {
               e.printStackTrace();

           }
       }
   }

    public static void main( String[] args ) throws Exception
    {
        LoggerContext loggerContext = (LoggerContext) LoggerFactory.getILoggerFactory();
        Logger rootLogger = loggerContext.getLogger("io.grpc");
        ((ch.qos.logback.classic.Logger) rootLogger).setLevel(Level.OFF);

        Logger rootLogger1 = loggerContext.getLogger("org.hyperledger");
        ((ch.qos.logback.classic.Logger) rootLogger1).setLevel(Level.OFF);



        Logger rootLogger2 = loggerContext.getLogger("io.netty");
        ((ch.qos.logback.classic.Logger) rootLogger2).setLevel(Level.OFF);

        Logger rootLogger3 = loggerContext.getLogger("blockchain.service");
        ((ch.qos.logback.classic.Logger) rootLogger3).setLevel(Level.OFF);

        Logger rootLogger4 = loggerContext.getLogger("blockchain.main");
        ((ch.qos.logback.classic.Logger) rootLogger4).setLevel(Level.OFF);


        if(args.length > 0) {
            String tenderMint = args[0];
            if(tenderMint.equals("tm")) {
                Server server = ServerBuilder.forPort(8080)
                        .addService(new TenderMintLedgerImpl())
                        .build();

                server.start();
                // Server threads are running in the background.
                System.out.println("Server started***********");
                // Don't exit the main thread. Wait until server is terminated.
                server.awaitTermination();
            }
        } else {
//         Create a new server to listen on port 8080
            ChaincodeService chaincodeService = new ChaincodeServiceImpl();

            Server server = ServerBuilder.forPort(8080)
                    .addService(new LedgerServiceImpl(chaincodeService))
                    .build();
//
//         Start the server
            server.start();

            // Server threads are running in the background.
            System.out.println("Server started***********");


//        System.out.println("Bootstrap ledger service.................");
            //Bootstrap the hyperledger
            new LedgerInstance(chaincodeService).bootStrapLedger();

            // Don't exit the main thread. Wait until server is terminated.
            server.awaitTermination();

        }


    }
}
