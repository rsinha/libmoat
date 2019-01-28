package blockchain.main;

import blockchain.service.ChaincodeService;
import blockchain.service.ChaincodeServiceImpl;
import io.grpc.Server;
import io.grpc.ServerBuilder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.logging.Level;

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

           } catch (Exception e) {
               e.printStackTrace();

           }
       }
   }

    public static void main( String[] args ) throws Exception
    {
//         Create a new server to listen on port 8080
        ChaincodeService chaincodeService = new ChaincodeServiceImpl();

        Logger.getLogger("io.grpc").setLevel(Level.INFO);
        Logger.getLogger("org.hyperledger").setLevel(Level.INFO);

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
