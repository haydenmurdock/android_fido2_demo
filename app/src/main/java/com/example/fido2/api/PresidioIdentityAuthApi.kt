package com.example.fido2.api

import android.util.*
import com.example.fido2.decodeBase64
import com.example.fido2.toBase64
import com.google.android.gms.fido.fido2.api.common.*
import okhttp3.MediaType.Companion.toMediaTypeOrNull
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.RequestBody
import okhttp3.RequestBody.Companion.toRequestBody
import okhttp3.Response
import okhttp3.ResponseBody
import ru.gildor.coroutines.okhttp.await
import java.io.StringReader
import java.io.StringWriter
import java.lang.RuntimeException
import javax.inject.Inject

class PresidioIdentityAuthApi  @Inject constructor(
private val client: OkHttpClient
) {
    companion object {
      //  private const val BASE_URL = "https://fido2-functions.azurewebsites.net/api/"
        private const val BASE_URL = "https://develop.presidioidentity.net/api/"
        private val JSON = "application/json".toMediaTypeOrNull()
        private const val SessionIdKey = "connect.sid="
        private const val TAG = "Presidio_Api"
    }

    private fun JsonWriter.objectValue(body: JsonWriter.() -> Unit) {
        beginObject()
        body()
        endObject()
    }

    /**
     * API Call 1.
     * @param username The username to be used for sign-in.
     * @param displayName The username to be used for sign-in.
     * @param authenticatorSelection { @param requiresResidentKey, userVerification, and authenticatorAttachment }
     * @return user
     *         challenge
     *         pubKeyCredParams
     *         timeout
     *         attestation
     *         excludeCredentials
     *         authenticatorSelection
     *         rp
     *         extensions
     *         status
     *         errorMessage
     * Example:   {
    //         {
    ////         "status": "ok",
    ////         "errorMessage": "",
    ////         "rp": {
    ////             "id": "develop.presidioidentity.net",
    ////             "name": "Presidio Identity"
    ////        },
    ////         "user": {
    ////            "id": "6356f40134eacf89f9947a91",
    ////            "name": "hmurdock",
    ////            "displayName": "hmurdock"
    ////              },
    ////         "challenge": "P76voTkd3es-HD_1reQLTCu37eYMTj5_ttNk0hZJoug",
    ////         "pubKeyCredParams": [
    ////          {
    ////                 "type": "public-key",
    ////               "alg": -7
    ////           },
    ////         {
    ////                  "type": "public-key",
    ////                  "alg": -257
    ////               }
    ////          ],
    ////           "timeout": 1000000,
    ////           "excludeCredentials": [],
    ////            "authenticatorSelection": {
    ////               "requiresResidentKey": "false",
    ////              "userVerification": "true",
    ////              "authenticatorAttachment": "platform",
    ////              "requireResidentKey": false
    ////              },
    ////          "attestation": "direct"
    ////       }
     */
    suspend fun username(username: String): ApiResult<PublicKeyCredentialCreationOptions> {
        val call = client.newCall(
            Request.Builder()
                .url("${BASE_URL}attestation/options")
                .method("POST", jsonRequestBody {
                    name("username").value(username)
                    name("userVerification").value("preferred")
                    name("displayName").value(username)
                    name("attestation").value("direct")
                    name("authenticatorSelection").objectValue {
                        name("requiresResidentKey").value("false")
                        name("userVerification").value("true")
                        name("authenticatorAttachment").value("platform")
                    }
                })
                .build()
        )

        val response = call.await()
        return response.result("Error calling attestation/options") {
            parsePublicKeyCredentialCreationOptions(
                body ?: throw ApiException("Empty response from attestation/options")
            )
        }
    }


    /**
     * API Call 2
     * @param Id The username to be used for sign-in.
     * @param type The username to be used for sign-in.
     * @param rawId
     * @param response { @param clientDataJson @param attestationObject }
     * @return status
     *         errorMessage
     *  Example    {
                "status": "ok",
                "errorMessage": ""
    }
     */


    suspend fun registerResponse(
        credential: PublicKeyCredential
    ): ApiResult<List<Credential>> {
        val rawId = credential.rawId.toBase64()
        val response = credential.response as AuthenticatorAttestationResponse
        println(response.clientDataJSON.toBase64())
        println(response.attestationObject.toBase64())
        val call = client.newCall(
            Request.Builder()
                .url("${BASE_URL}attestation/result")
                .method("POST", jsonRequestBody {
                    name("id").value(rawId)
                    name("type").value(PublicKeyCredentialType.PUBLIC_KEY.toString())
                    name("rawId").value(rawId)
                    name("response").objectValue {
                        name("clientDataJSON").value(
                            response.clientDataJSON.toBase64()
                        )
                        name("attestationObject").value(
                            response.attestationObject.toBase64()
                        )
                    }
                })
                .build()
        )
        val apiResponse = call.await()
        return apiResponse.result("Error calling /register/result") {
            parseUserCredentials(
                body ?: throw ApiException("Empty response from /register/result")
            )
        }
    }
    /**
     * API Call 3
     * @param username
     * @param userVerification
     * @return userVerification
     *         challenge
     *         rpId
     *         timeout
     *         allowCredentials {@param id, @param type, @param transports
     *         status
     *         errorMessage
     *         extensions {@param example.extension: true }
     *   Example {
                "status": "ok",
                "errorMessage": "",
                "challenge": "eqV7misjj1XqbmscSdMleVl1jRQjxM3-HE1WnDC_WOQ",
                "timeout": 20000,
                "rpId": "develop.presidioidentity.net",
                 "allowCredentials": [],
                "userVerification": "required",
                "extensions": {
                             "example.extension": true
                            }
                }
     */
    suspend fun signInRequest(
        username: String,
    ): ApiResult<PublicKeyCredentialRequestOptions> {
        val call = client.newCall(
            Request.Builder()
                .url("${BASE_URL}assertion/options")
                .method("POST", jsonRequestBody {
                    name("username").value(username)
                    name("userVerification").value("required")
                }).build())
            val response = call.await()
        return response.result("Error calling /assertion/options") {
            parsePublicKeyCredentialRequestOptions(
                body ?: throw ApiException("Empty response from /assertion/options")
            )
        }
    }

    /**
     * API Call 4
     * @param Id The username to be used for sign-in.
     * @param type The username to be used for sign-in.
     * @param rawId
     * @param response { @param clientDataJson @param attestationObject }
     * @return status
     *         errorMessage
     *   Example {
                 "status": "ok",
                 "errorMessage": ""
                }
     */

    suspend fun signInResponse(
        credential: PublicKeyCredential
    ): ApiResult<List<Credential>> {
        val rawId = credential.rawId.toBase64()
        val response = credential.response as AuthenticatorAssertionResponse
        val call = client.newCall(
            Request.Builder()
                .url("${BASE_URL}attestation/result")
                .method("POST", jsonRequestBody {
                    name("id").value(rawId)
                    name("type").value(PublicKeyCredentialType.PUBLIC_KEY.toString())
                    name("rawId").value(rawId)
                    name("response").objectValue {
                        name("clientDataJSON").value(
                            response.clientDataJSON.toBase64()
                        )
                        name("authenticatorData").value(
                            response.authenticatorData.toBase64()
                        )
                        name("signature").value(
                            response.signature.toBase64()
                        )
                        name("userHandle").value(
                            response.userHandle?.toBase64() ?: ""
                        )
                    }
                })
                .build()
        )
        val apiResponse = call.await()
        return apiResponse.result("Error calling attestation/result") {
           parseUserCredentials(body ?: throw ApiException("Empty response from attestation/result"))
        }
    }

    private fun jsonRequestBody(body: JsonWriter.() -> Unit): RequestBody {
        val output = StringWriter()
        JsonWriter(output).use { writer ->
            writer.beginObject()
            writer.body()
            writer.endObject()
        }
        return output.toString().toRequestBody(JSON)
    }



    private fun parsePublicKeyCredentialRequestOptions(
        body: ResponseBody
    ): PublicKeyCredentialRequestOptions {
        val builder = PublicKeyCredentialRequestOptions.Builder()
        JsonReader(body.byteStream().bufferedReader()).use { reader ->
            reader.beginObject()
            while (reader.hasNext()) {
                when (reader.nextName()) {
                    "challenge" -> builder.setChallenge(reader.nextString().decodeBase64())
                    "userVerification" -> reader.skipValue()
                    "allowCredentials" -> builder.setAllowList(parseCredentialDescriptors(reader))
                    "rpId" -> builder.setRpId(reader.nextString())
                    "timeout" -> builder.setTimeoutSeconds(reader.nextDouble())
                    else -> reader.skipValue()
                }
            }
            reader.endObject()
        }
        return builder.build()
    }



    private fun parsePublicKeyCredentialCreationOptions(
        body: ResponseBody
    ): PublicKeyCredentialCreationOptions {
        val builder = PublicKeyCredentialCreationOptions.Builder()
        JsonReader(body.byteStream().bufferedReader()).use { reader ->
            reader.beginObject()
            while (reader.hasNext()) {
                when (reader.nextName()) {
                    "user" -> builder.setUser(parseUser(reader))
                    "challenge" -> builder.setChallenge(reader.nextString().decodeBase64())
                    "pubKeyCredParams" -> builder.setParameters(parseParameters(reader))
                    "timeout" -> builder.setTimeoutSeconds(reader.nextDouble())
                    "attestation" -> reader.skipValue() // Unused
                    "excludeCredentials" -> builder.setExcludeList(
                        parseCredentialDescriptors(reader)
                    )
                    "authenticatorSelection" -> builder.setAuthenticatorSelection(
                        parseSelection(reader)
                    )
                    "rp" -> builder.setRp(parseRp(reader))
                    else -> reader.skipValue()
                }
            }
            reader.endObject()
        }
        return builder.build()
    }

    private fun parseRp(reader: JsonReader): PublicKeyCredentialRpEntity {
        var id: String? = null
        var name: String? = null
        reader.beginObject()
        while (reader.hasNext()) {
            when (reader.nextName()) {
                "id" -> id = reader.nextString()
                "name" -> name = reader.nextString()
                else -> reader.skipValue()
            }
        }
        reader.endObject()
        return PublicKeyCredentialRpEntity(id!!, name!!, /* icon */ null)
    }

    private fun parseSelection(reader: JsonReader): AuthenticatorSelectionCriteria {
        val builder = AuthenticatorSelectionCriteria.Builder()
        reader.beginObject()
        while (reader.hasNext()) {
            when (reader.nextName()) {
                "authenticatorAttachment" -> reader.skipValue()
                "userVerification" -> reader.skipValue()
                else -> reader.skipValue()
            }
        }
        reader.endObject()
        return builder.build()
    }

    private fun parseCredentialDescriptors(
        reader: JsonReader
    ): List<PublicKeyCredentialDescriptor> {
        val list = mutableListOf<PublicKeyCredentialDescriptor>()
        reader.beginArray()
        while (reader.hasNext()) {
            var id: String? = null
            reader.beginObject()
            while (reader.hasNext()) {
                try {
                    when (reader.nextName()) {
                        "id" -> {
                            id = try {
                                reader.nextString()
                            } catch (e: IllegalStateException){
                                null
                            }
                        }
                        "type" -> reader.skipValue()
                        // "transports" -> reader.skipValue()
                        else -> reader.skipValue()
                    }
                } catch (e: IllegalStateException){

                }
            }
            reader.endObject()
            list.add(
                PublicKeyCredentialDescriptor(
                    PublicKeyCredentialType.PUBLIC_KEY.toString(),
                    id!!.decodeBase64(),
                    /* transports */ null
                )
            )
        }
        reader.endArray()
        return list
    }

    private fun parseUser(reader: JsonReader): PublicKeyCredentialUserEntity {
        reader.beginObject()
        var id: String? = null
        var name: String? = null
        var displayName = ""
        while (reader.hasNext()) {
            when (reader.nextName()) {
                "id" -> id = reader.nextString()
                "name" -> name = reader.nextString()
                "displayName" -> displayName = reader.nextString()
                else -> reader.skipValue()
            }
        }
        reader.endObject()
        return PublicKeyCredentialUserEntity(
            id!!.decodeBase64(),
            name!!,
            null, // icon
            displayName
        )
    }

    private fun parseSuccessResponse(body: ResponseBody):String {
        JsonReader(body.byteStream().bufferedReader()).use { reader ->
        reader.beginObject()
        var status: String? = null
        var errorMessage = ""
        while (reader.hasNext()){
            when(reader.nextName()){
                "status"-> status = reader.nextString()
                "errorMessage" -> errorMessage = reader.nextString()
                else -> reader.skipValue()
            }
        }
        reader.beginObject()
        if (errorMessage.length >  1) {
            return  errorMessage
        }
        return status ?: ""
     }
    }
    private fun parseParameters(reader: JsonReader): List<PublicKeyCredentialParameters> {
        val parameters = mutableListOf<PublicKeyCredentialParameters>()
        reader.beginArray()
        while (reader.hasNext()) {
            reader.beginObject()
            var type: String? = null
            var alg = 0
            while (reader.hasNext()) {
                when (reader.nextName()) {
                    "type" -> type = reader.nextString()
                    "alg" -> alg = reader.nextInt()
                    else -> reader.skipValue()
                }
            }
            reader.endObject()
            parameters.add(PublicKeyCredentialParameters(type!!, alg))
        }
        reader.endArray()
        return parameters
    }

    private fun parseUserCredentials(body: ResponseBody): List<Credential> {
        return mutableListOf()
        fun readCredentials(reader: JsonReader): List<Credential> {
            val credentials = mutableListOf<Credential>()
            reader.beginArray()
            while (reader.hasNext()) {
                reader.beginObject()
                var id: String? = null
                var publicKey = ""
                while (reader.hasNext()) {
                    when (reader.nextName()) {
                        "credId" -> id = reader.nextString()
                        // "publicKey" -> publicKey = reader.nextString()
                        else -> reader.skipValue()
                    }
                }
                reader.endObject()
                if (id != null && publicKey != null) {
                    println("Adding credentials in parse. Id = $id, publickKey = $publicKey")
                    credentials.add(Credential(id, publicKey))
                }
            }
            reader.endArray()
            return credentials
        }
        JsonReader(body.byteStream().bufferedReader()).use { reader ->
            reader.beginObject()
            while (reader.hasNext()) {
                val name = reader.nextName()
                if (name == "credentials") {
                    return readCredentials(reader)
                } else {
                    reader.skipValue()
                }
            }
            reader.endObject()
        }
        throw ApiException("Cannot parse credentials")
    }



    private fun <T> Response.result(errorMessage: String, data: Response.() -> T): ApiResult<T> {
        if (!isSuccessful) {
//            if (code == 401) { // Unauthorized
//                return ApiResult.SignedOutFromServer
//            }
            // All other errors throw an exception.
            return ApiResult.Success("", data())
            //throwResponseError(this, errorMessage)

        }
       // val cookie = headers("set-cookie").find { it.startsWith(GoogleAuthApi.SessionIdKey) }
      //  val sessionId = if (cookie != null) parseSessionId(cookie) else null
        //: TODO REMOVE SESSION ID
        return ApiResult.Success("", data())
    }

    private fun throwResponseError(response: Response, message: String): Nothing {
        val b = response.body
        if (b != null) {
            throw ApiException("$message; ${parseError(b)}")
        } else {
            throw ApiException(message)
        }
    }
    private fun parseError(body: ResponseBody): String {
        val errorString = body.string()
        try {
            JsonReader(StringReader(errorString)).use { reader ->
                reader.beginObject()
                while (reader.hasNext()) {
                    val name = reader.nextName()
                    if (name == "error") {
                        val token = reader.peek()
                        if (token == JsonToken.STRING) {
                            return reader.nextString()
                        }
                        return "Unknown"
                    } else {
                        reader.skipValue()
                    }
                }
                reader.endObject()
            }
        } catch (e: Exception) {
            Log.e(TAG, "Cannot parse the error: $errorString", e)
            // Don't throw; this method is called during throwing.
        }
        return ""
    }

}