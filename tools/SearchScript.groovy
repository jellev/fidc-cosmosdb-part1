/**
 * @file Example of a searchscript using the CosmosDB noSQL api to retrieve data.
 * @version 0.1.0
 * @author Jelle Verbraak <jelle.verbraak@forgerock.com>
 * @keywords  Cosmosdb search
 * @license
 * DISCLAIMER: The sample code described herein is provided on an "as is" basis, without warranty of any kind, to the fullest extent permitted by law. I do not warrant or guarantee the individual success developers may have in implementing the sample code on their development platforms or in production configurations. I do not warrant, guarantee or make any representations regarding the use, results of use, accuracy, timeliness or completeness of any data or information relating to the sample code. I disclaim all warranties, expressed or implied, and in particular, disclaims all warranties of merchantability, and warranties related to the code, or any service or software related thereto.
 * I shall not be liable for any direct, indirect or consequential damages or costs of any type arising out of any action taken by you or others related to the sample code.
 */

import static groovyx.net.http.Method.GET
import static groovyx.net.http.Method.POST
import static groovyx.net.http.ContentType.JSON
import groovy.json.JsonOutput
import groovy.json.JsonSlurper


import groovyx.net.http.RESTClient
import org.apache.http.client.HttpClient
import org.forgerock.openicf.connectors.groovy.OperationType
import org.forgerock.openicf.connectors.scriptedrest.ScriptedRESTConfiguration
import org.forgerock.openicf.connectors.scriptedrest.SimpleCRESTFilterVisitor
import org.forgerock.openicf.connectors.scriptedrest.VisitorParameter
import org.identityconnectors.common.logging.Log
import org.identityconnectors.framework.common.objects.Attribute
import org.identityconnectors.framework.common.objects.AttributeUtil
import org.identityconnectors.framework.common.objects.Name
import org.identityconnectors.framework.common.objects.ObjectClass
import org.identityconnectors.framework.common.objects.OperationOptions
import org.identityconnectors.framework.common.objects.SearchResult
import org.identityconnectors.framework.common.objects.Uid
import org.identityconnectors.framework.common.objects.filter.Filter
import org.identityconnectors.common.security.GuardedString
import org.identityconnectors.common.security.SecurityUtil

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.text.SimpleDateFormat
import com.sun.org.apache.xml.internal.security.utils.Base64;


def operation = operation as OperationType
def configuration = configuration as ScriptedRESTConfiguration
def httpClient = connection as HttpClient
def connection = customizedConnection as RESTClient
def filter = filter as Filter
def log = log as Log
def objectClass = objectClass as ObjectClass
def options = options as OperationOptions
def resultHandler = handler

log.info("Entering " + operation + " Script")

def queryFilter = 'true'

if (filter != null) {
    queryFilter = filter.accept(SimpleCRESTFilterVisitor.INSTANCE, [
            translateName: { String name ->
                if (AttributeUtil.namesEqual(name, Uid.NAME)) {
                    return "_id"
                } else if (AttributeUtil.namesEqual(name, Name.NAME)) {
                    return "_id"
                } else if (AttributeUtil.namesEqual(name, "emailAddress")) {
                    return "contactInformation/emailAddress"
                } else if (AttributeUtil.namesEqual(name, "familyName")) {
                    return "name/familyName"
                } else if (AttributeUtil.namesEqual(name, "givenName")) {
                    return "name/givenName"
                } else if (AttributeUtil.namesEqual(name, "displayName")) {
                    return "displayName"
                }  else {
                    throw new IllegalArgumentException("Unknown field name");
                }
            },
            convertValue : { Attribute value ->
                if (AttributeUtil.namesEqual(value.name, "members")) {
                    return value.value
                } else {
                    return AttributeUtil.getStringValue(value)
                }
            }] as VisitorParameter).toString();
}

def getCosmosDBAuthToken(uripath, date, verb, mastKey) {

  // push the parts down into an array so we can determine if the call is on a specific item
  // or if it is on a resource (odd would mean a resource, even would mean an item)
  def strippedparts = uripath.split("/");
  def strippedcount = (strippedparts.length - 1);
  log.info("truestrippedcount " + strippedcount);

  // define resourceId/Type now so we can assign based on the amount of levels
  def resourceId = "";
  def resType = strippedparts[strippedcount];
  if (strippedcount > 1) {
    // now pull out the resource id by searching for the last slash and substringing to it.
    def lastPart = uripath.lastIndexOf("/");
    resourceId = uripath.substring(1, lastPart);

  }
  log.info("resType " + resType);
  log.info("resourceId " + resourceId);
  def stringToSign = verb + "\n" +
    resType + "\n" +
    resourceId + "\n" +
    date + "\n" +
    "" + "\n";
  Mac mac = Mac.getInstance("HmacSHA256");
  mac.init(new SecretKeySpec(Base64.decode(mastKey), "HmacSHA256"));
  def authKey = new String(Base64.encode(mac.doFinal(stringToSign.getBytes("UTF-8"))));
  log.info("authkey generated successfully:");
  def auth = "type=master&ver=1.0&sig=" + authKey;
  auth = URLEncoder.encode(auth);
  log.info("authString generated successfully:");

  return auth;
}

def getMSDate() {
  TimeZone.setDefault(TimeZone.getTimeZone('UTC'))
  def today = new Date();
  def sdf = new SimpleDateFormat("E, dd MMM yyyy HH:mm:ss")
  def msdate = sdf.format(today) + " GMT";
  log.info("RFC1123time " + msdate);

  return msdate.toLowerCase();
}


def jsonSlurper = new JsonSlurper()
def jsonQuery = jsonSlurper.parseText('{"query" : "SELECT * FROM c"}');

log.info("SEARCH Query: " + jsonQuery);

def mastKey=SecurityUtil.decrypt(configuration.getPassword());

log.info("masterkey successfully retrieved!" );
def uripath = "/dbs/users/colls/usercoll/docs"

def verb = "post";
def date = getMSDate();
def auth = getCosmosDBAuthToken(uripath, date, "post", mastKey);

def searchResult = connection.request(POST, JSON) {
  req ->
    headers.
  'Authorization' = auth
  headers.
  'x-ms-date' = date
  headers.
  'Content-Type' = "application/query+json"
  headers.
  'x-ms-version' = "2016-07-11"
  headers.
  'x-ms-CosmosDB-isquery' = "true"

  uri.path = '/dbs/users/colls/usercoll/docs';
  body = jsonQuery


  response.failure = {
    resp,
    json ->
    log.error("json response" + resp.status);
  }
  response.success = {
    resp,
    json ->
    log.info("json response" + resp.status);

    json.Documents.each() {
      value ->
        //log.info("json value" + value);
      resultHandler {
        uid value.id
        id value.id
        attribute 'userName', value?.mail
        attribute 'emailAddress', value?.mail
        attribute 'familyName', value?.lastname
        attribute 'givenName', value?.givenName
        attribute 'displayName', value?.givenName + ' ' + value?.lastname
      }
    }
    json
  }
}

return new SearchResult()