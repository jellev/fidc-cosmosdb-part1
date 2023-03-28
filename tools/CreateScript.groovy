/*
 * Copyright 2014-2020 ForgeRock AS. All Rights Reserved
 *
 * Use of this code requires a commercial software license with ForgeRock AS.
 * or with one of its affiliates. All use shall be exclusively subject
 * to such license between the licensee and ForgeRock AS.
 */

import static groovyx.net.http.ContentType.JSON

import groovy.json.JsonBuilder
import groovyx.net.http.RESTClient
import org.apache.http.client.HttpClient
import org.forgerock.openicf.connectors.groovy.OperationType
import org.forgerock.openicf.connectors.scriptedrest.ScriptedRESTConfiguration
import org.identityconnectors.common.logging.Log
import org.identityconnectors.framework.common.objects.Attribute
import org.identityconnectors.framework.common.objects.AttributesAccessor
import org.identityconnectors.framework.common.objects.ObjectClass
import org.identityconnectors.framework.common.objects.OperationOptions


def operation = operation as OperationType
def createAttributes = new AttributesAccessor(attributes as Set<Attribute>)
def configuration = configuration as ScriptedRESTConfiguration
def httpClient = connection as HttpClient
def connection = customizedConnection as RESTClient
def name = id as String
def log = log as Log
def objectClass = objectClass as ObjectClass
def options = options as OperationOptions

log.info("Entering " + operation + " Script");


def builder = new JsonBuilder()
builder {
    customer {
        userName(createAttributes.hasAttribute("emailAddress") ? createAttributes.findString("emailAddress") : "")
        phone(createAttributes.hasAttribute("telephoneNumber") ? createAttributes.findString("telephoneNumber") : "")
        email(createAttributes.hasAttribute("emailAddress") ? createAttributes.findString("emailAddress") : "")
        last_name(createAttributes.hasAttribute("familyName") ? createAttributes.findString("familyName") : "")
        first_name(createAttributes.hasAttribute("givenName") ? createAttributes.findString("givenName") : "")
        total_spent(createAttributes.hasAttribute("totalspent") ? createAttributes.findString("totalspent") : "")
        accepts_marketing(createAttributes.hasAttribute("marketing") ? createAttributes.findBoolean("marketing") : false)
        note(createAttributes.hasAttribute("note") ? createAttributes.findString("note") : "")        
    }
}

//if (createAttributes.hasAttribute("password")) {
//    builder.content["password"] = createAttributes.findString("password")
//}


def response = connection.post(
        path: '/admin/api/2020-10/customers.json',
        headers: ['Cache-Control': 'max-age=0'],
        contentType: JSON,
        requestContentType: JSON,
        body: builder.toString());

log.error("JONK: " + response.data);

return response.data.customer.id.toString();
