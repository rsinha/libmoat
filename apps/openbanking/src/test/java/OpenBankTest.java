import com.plaid.client.response.TransactionsGetResponse;
import org.junit.Test;

import java.util.ArrayList;
import java.util.Date;
import java.util.List;

public class OpenBankTest {
    private static final String institutionId = "ins_109511"; //TARTAN_BANK_INSTITUTION_ID = "ins_109511";
    private BankApiCredentials bac = new BankApiCredentials(false);
    private OpenBank openBank = new OpenBank(bac,institutionId);

    @Test
    public void testGetTransactions() {

        String accessToken = "";
        try{
            accessToken = openBank.getAccessToken("user_good", "pass_good");
        } catch (Exception e) {
            e.printStackTrace();
        }

        Date startDate = new Date(System.currentTimeMillis() - 86400000L * 100);
        Date endDate = new Date();
        List<TransactionsGetResponse.Transaction> tx = new ArrayList<TransactionsGetResponse.Transaction>();
        try {
            tx = openBank.getTransactions(accessToken, startDate, endDate);
            System.out.printf("Total:", tx.size());
        } catch (Exception e) {
            e.printStackTrace();
        }



    }


}
