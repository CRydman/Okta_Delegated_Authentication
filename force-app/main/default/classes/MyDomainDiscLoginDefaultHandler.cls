// This sample class contains the default logic for My Domain login discovery by password. 
// You can customize the code to ensure it meets your needs. The requestAttributes parameter
// provides additional information you can use in the discovery logic. Attributes include MyDomainUrl, 
// IpAddress, UserAgent, and location information (such as Country and City). 
// Use Auth.DiscoveryCustomErrorException to throw custom errors which will be shown on login page.
 global class MyDomainDiscLoginDefaultHandler implements Auth.MyDomainLoginDiscoveryHandler {
  global Boolean isSso;
  global PageReference login(String identifier, String startUrl, Map<String, String> requestAttributes) {
   if (identifier != null) {
        // Search for user by Federation ID
        List<User> userList = [SELECT Id FROM User WHERE FederationIdentifier = :identifier AND IsActive = TRUE WITH SYSTEM_MODE];

        // Checks if a user was found
        if (!userList.isEmpty() && userList.size() == 1) {
          
          //Maps the record ID to the record for the user
          Map<Id, User> userMap = new Map<Id,User>();
          userMap.putAll(userList);

          //Checks if the user has Login with SSO only enabled
          List<User> ssoList = [SELECT Id FROM User WHERE FederationIdentifier = :identifier AND Login_with_SSO_only__c = TRUE WITH SYSTEM_MODE];
          Map<Id, User> ssoMap = New Map<Id, User>(ssoList);

          //Checks if the user was found and has Login with SSO only enabled. Saves the answer as a variable
          if( userMap.equals(ssoMap)) {
            isSso = true;
          } else {
            isSso = false;
          }
            return discoveryResult(userList[0], startUrl, requestAttributes);
        } else {
            throw new Auth.LoginDiscoveryException('No unique user found. User count=' + userList.size());
        }
    }
    throw new Auth.LoginDiscoveryException('Invalid Identifier');
  }
    private PageReference getSsoRedirect(User user, String startUrl, Map<String, String> requestAttributes) {
     // API name of the SAML IDP
     String idpName = 'Okta';

     // Look up if the user has access to the IDP and return the URL to initialize SSO.
     SamlSsoConfig sso = [select Id from SamlSsoConfig where DeveloperName = :idpName WITH SYSTEM_MODE limit 1];
     
     // To get the URL for a My Domain subdomain, you can pass null in the communityURL parameter.
     String ssoUrl = Auth.AuthConfiguration.getSamlSsoUrl(null, startUrl, SSO.Id);
     return new PageReference(ssoUrl);
  }
     private PageReference discoveryResult(User user, String startUrl, Map<String, String> requestAttributes) 
     {
     PageReference ssoRedirect = null;
     try { ssoRedirect = getSsoRedirect(user, startUrl, requestAttributes); }
     catch(Exception e) { ssoRedirect = null; }

     if(ssoRedirect != null &&
      isSso == true)
     {
       return ssoRedirect;
     } 
      else {
        return Auth.SessionManagement.finishLoginDiscovery(Auth.LoginDiscoveryMethod.password, user.Id);    
      }
   }
}