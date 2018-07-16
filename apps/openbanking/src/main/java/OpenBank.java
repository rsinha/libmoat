import com.plaid.client.*;
import com.plaid.client.request.ItemCreateRequest;
import com.plaid.client.request.ItemPublicTokenCreateRequest;
import com.plaid.client.request.TransactionsGetRequest;
import com.plaid.client.request.common.Product;
import com.plaid.client.response.ItemCreateResponse;
import com.plaid.client.response.ItemPublicTokenCreateResponse;
import com.plaid.client.response.TransactionsGetResponse;
import retrofit2.Response;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.List;

public class OpenBank {

    private BankApiCredentials bac = null;

    private PlaidClient plaidClient = null;

    private static String institutionId = "";

    public OpenBank(BankApiCredentials bac, String institutionId) {
        this.bac = bac;
        this.institutionId = institutionId;
        plaidClient = plaidClient();
    }


    public String getAccessToken(String userName, String passCode) throws Exception {
        if (bac != null && plaidClient != null) {
            Response<ItemPublicTokenCreateResponse> publicTokenResp = plaidClient.service().itemPublicTokenCreate(
                    new ItemPublicTokenCreateRequest(getItemCreateResponse(userName, passCode).body().getAccessToken())
            ).execute();

            return publicTokenResp.body().getPublicToken();

        }
        return null;
    }

    public List<TransactionsGetResponse.Transaction> getTransactions(String accessToken, Date start, Date end) throws Exception {
        TransactionsGetRequest request = new TransactionsGetRequest(accessToken, start, end).withCount(100);

        Response<TransactionsGetResponse> response = plaidClient.service().transactionsGet(request).execute();
        List<TransactionsGetResponse.Transaction> transactions = new ArrayList<TransactionsGetResponse.Transaction>();

        for(TransactionsGetResponse.Transaction tx: response.body().getTransactions()) {
            transactions.add(tx);
        }
        return transactions;

    }


    private PlaidClient plaidClient() {
        if (this.bac.isSandbox())
            return PlaidClient.newBuilder().clientIdAndSecret(this.bac.clientId(), this.bac.environmentSecret())
                    .publicKey(this.bac.publicKey()).sandboxBaseUrl().build();
        else
            return PlaidClient.newBuilder().clientIdAndSecret(this.bac.clientId(), this.bac.environmentSecret())
                    .publicKey(this.bac.publicKey()).developmentBaseUrl().build();
    }

    private Response<ItemCreateResponse> getItemCreateResponse(String userName, String passCode) throws Exception {
        Response<ItemCreateResponse> response = plaidClient.service().itemCreate(
                new ItemCreateRequest(
                        institutionId, Arrays.asList(Product.TRANSACTIONS)
                ).withCredentials("username", userName).withCredentials("password", passCode)
        ).execute();

        return response;
    }


}
