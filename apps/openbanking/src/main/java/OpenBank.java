import com.plaid.client.*;
import com.plaid.client.request.ItemCreateRequest;
import com.plaid.client.request.ItemPublicTokenCreateRequest;
import com.plaid.client.request.ItemPublicTokenExchangeRequest;
import com.plaid.client.request.TransactionsGetRequest;
import com.plaid.client.request.common.Product;
import com.plaid.client.response.ItemCreateResponse;
import com.plaid.client.response.ItemPublicTokenCreateResponse;
import com.plaid.client.response.ItemPublicTokenExchangeResponse;
import com.plaid.client.response.TransactionsGetResponse;
import com.plaid.client.request.common.BaseAccessTokenRequest;
import com.plaid.client.request.common.BasePublicRequest;
import com.plaid.client.response.BaseResponse;
import com.plaid.client.response.Account;
import okhttp3.logging.HttpLoggingInterceptor;
import retrofit2.Call;
import retrofit2.http.Body;
import retrofit2.http.POST;
import retrofit2.Response;

import java.util.*;

public class OpenBank {

    private BankApiCredentials bac = null;

    private PlaidClient plaidClient = null;

    private static String institutionId = "";
    private PlaidLinkService plaidLinkService = null;

    public OpenBank(BankApiCredentials bac, String institutionId) {
        this.bac = bac;
        this.institutionId = institutionId;
        plaidClient = plaidClient();
        plaidLinkService = plaidClient.getRetrofit().create(PlaidLinkService.class);
    }

    public interface PlaidLinkService {
        class LinkItemCreateRequest extends BasePublicRequest {
            private final Map<String, String> credentials;
            private final List<Product> initialProducts;
            private final String institutionId;

            public LinkItemCreateRequest(Map<String, String> credentials, List<Product> initialProducts, String institutionId) {
                this.credentials = credentials;
                this.initialProducts = initialProducts;
                this.institutionId = institutionId;
            }
        }

        // link endpoints
        // not intended to be part of the server-side API
        // implemented here for ease of testing flows involving link
        class LinkItemCreateResponse extends BaseResponse {
            private List<Account> accounts;
            private String publicToken;

            public List<Account> getAccounts() {
                return accounts;
            }

            public String getPublicToken() {
                return publicToken;
            }
        }

        @POST("/link/item/create")
        Call<LinkItemCreateResponse> linkItemCreate(@Body LinkItemCreateRequest request);

    }


    public String getAccessToken(String userName, String passCode) throws Exception {
        if (bac != null && plaidClient != null) {

            Map<String, String> credentials = new HashMap<String, String>();
            credentials.put("username", userName);
            credentials.put("password", passCode);
            Response <PlaidLinkService.LinkItemCreateResponse> response = plaidLinkService.linkItemCreate(new PlaidLinkService.LinkItemCreateRequest(
                    credentials, Arrays.asList(Product.AUTH, Product.TRANSACTIONS), institutionId
            )).execute();
            String linkToken = response.body().getPublicToken();

            Response<ItemPublicTokenExchangeResponse> pteResponse = plaidClient.service().itemPublicTokenExchange(
                    new ItemPublicTokenExchangeRequest(linkToken)
            ).execute();
            return pteResponse.body().getAccessToken();
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
                    .publicKey(this.bac.publicKey())
                    .sandboxBaseUrl().logLevel(HttpLoggingInterceptor.Level.BODY).build();
        else
            return PlaidClient.newBuilder().clientIdAndSecret(this.bac.clientId(), this.bac.environmentSecret())
                    .publicKey(this.bac.publicKey())
                    .developmentBaseUrl().logLevel(HttpLoggingInterceptor.Level.BODY).build();
    }

}
