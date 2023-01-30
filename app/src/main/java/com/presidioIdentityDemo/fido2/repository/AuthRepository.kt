/*
 * Copyright 2019 Google Inc. All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.presidioIdentityDemo.fido2.repository

import android.app.PendingIntent
import android.util.Log
import androidx.datastore.core.DataStore
import androidx.datastore.preferences.core.Preferences
import androidx.datastore.preferences.core.edit
import androidx.datastore.preferences.core.stringPreferencesKey
import androidx.datastore.preferences.core.stringSetPreferencesKey
import com.presidioIdentityDemo.fido2.api.*
import com.presidioIdentityDemo.fido2.toBase64
import com.google.android.gms.fido.fido2.Fido2ApiClient
import com.google.android.gms.fido.fido2.api.common.PublicKeyCredential
import com.google.android.gms.fido.fido2.api.common.PublicKeyCredentialCreationOptions
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.channels.BufferOverflow
import kotlinx.coroutines.flow.MutableSharedFlow
import kotlinx.coroutines.flow.asSharedFlow
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.flow.map
import kotlinx.coroutines.launch
import kotlinx.coroutines.tasks.await
import javax.inject.Inject
import javax.inject.Singleton

/**
 * Works with the API, the local data store, and FIDO2 API.
 */
@Singleton
class AuthRepository @Inject constructor(
    private val presidioApi: PresidioIdentityAuthApi,
    private val dataStore: DataStore<Preferences>,
    scope: CoroutineScope
) {

    private companion object {
        const val TAG = "AuthRepository"

        // Keys for SharedPreferences
        val USERNAME = stringPreferencesKey("username")
        val SESSION_ID = stringPreferencesKey("session_id")
        val CREDENTIALS = stringSetPreferencesKey("credentials")
        val LOCAL_CREDENTIAL_ID = stringPreferencesKey("local_credential_id")

        suspend fun <T> DataStore<Preferences>.read(key: Preferences.Key<T>): T? {
            return data.map { it[key] }.first()
        }
    }

    private var fido2ApiClient: Fido2ApiClient? = null

    fun setFido2APiClient(client: Fido2ApiClient?) {
        fido2ApiClient = client
    }

    private val signInStateMutable = MutableSharedFlow<SignInState>(
        replay = 1,
        onBufferOverflow = BufferOverflow.DROP_OLDEST
    )
    /** The current [SignInState]. */
    val signInState = signInStateMutable.asSharedFlow()

    /**
     * The list of credentials this user has registered on the server. This is only populated when
     * the sign-in state is [SignInState.SignedIn].
     */
    val credentials =
        dataStore.data.map { it[CREDENTIALS] ?: emptySet() }.map { parseCredentials(it) }

    init {
        scope.launch {
            println("auth repo scope launch hit")
            val initialState = SignInState.SignedOut
            signInStateMutable.emit(initialState)

        }
    }

    /**
     * Sends the username to the server. If it succeeds, the sign-in state will proceed to
     * [SignInState.SigningIn].
     */
    suspend fun username(username: String) {
        when (val result = presidioApi.registerWith(username)) {
            ApiResult.SignedOutFromServer -> forceSignOut()
            is ApiResult.Success -> {
                DataHolder.setPkcco(result.data)
                signInStateMutable.emit(SignInState.SigningIn(username))
            }
        }
    }

    /**
     * Signs in with a password. This should be called only when the sign-in state is
     * [SignInState.SigningIn]. If it succeeds, the sign-in state will proceed to
     * [SignInState.SignedIn].
     */
    suspend fun password(userName: String) {
        signInStateMutable.emit(SignInState.SignedIn(userName))
    }

    /**
     * Retrieves the list of credential this user has registered on the server. This should be
     * called only when the sign-in state is [SignInState.SignedIn].
     */

    private fun List<Credential>.toStringSet(): Set<String> {
        return mapIndexed { index, credential ->
            "$index;${credential.id};${credential.publicKey}"
        }.toSet()
    }

    private fun parseCredentials(set: Set<String>): List<Credential> {
        return set.map { s ->
            val (index, id, publicKey) = s.split(";")
            index to Credential(id, publicKey)
        }.sortedBy { (index, _) -> index }
            .map { (_, credential) -> credential }
    }

    suspend fun signOut() {
        signInStateMutable.emit(SignInState.SignedOut)
    }

    private suspend fun forceSignOut() {
        signInStateMutable.emit(SignInState.SignedOut)
    }

    /**
     * Starts to register a new credential to the server. This should be called only when the
     * sign-in state is [SignInState.SignedIn].
     */
    suspend fun registerPresidioRequest(pkcco: PublicKeyCredentialCreationOptions):PendingIntent? {
        fido2ApiClient?.let {  client ->
            val task = client.getRegisterPendingIntent(pkcco)
            return task.await()
        }
        return null
    }

    /**
     * Finishes registering a new credential to the server. This should only be called after
     * a call to [registerRequest] and a local FIDO2 API for public key generation.
     */
    suspend fun registerResponse(credential: PublicKeyCredential) {
        try {
            when (val result = presidioApi.registerResponse(credential)) {
                ApiResult.SignedOutFromServer -> forceSignOut()
               is ApiResult.Success -> {
                    val name = dataStore.read(USERNAME)
                    if(!name.isNullOrBlank() && result.data.equals("ok")){
                        signInStateMutable.emit(SignInState.SignedIn(name))
                    } else {
                        signInStateMutable.emit(SignInState.SignInError(result.data))
                    }

                }
            }
        } catch (e: ApiException) {
            Log.e(TAG, "Cannot call registerResponse", e)
        }
    }

    /**
     * Starts to sign in with a FIDO2 credential. This should only be called when the sign-in state
     * is [SignInState.SigningIn].
     */
    suspend fun signInRequest(username: String): PendingIntent? {
        fido2ApiClient?.let { client ->
            when (val apiResult = presidioApi.signInWith(username)) {
                ApiResult.SignedOutFromServer -> forceSignOut()
                is ApiResult.Success -> {
                    val task = client.getSignPendingIntent(apiResult.data)
                    return task.await()
                }
            }
        }
      return null
    }

    /**
     * Finishes to signing in with a FIDO2 credential. This should only be called after a call to
     * [signinRequest] and a local FIDO2 API for key assertion.
     */
    suspend fun signinResponse(credential: PublicKeyCredential) {
        try {
            val username = dataStore.read(USERNAME) ?: ""
            val credentialId = credential.rawId.toBase64()
            when (val result = presidioApi.signInResponse(credential)) {
                ApiResult.SignedOutFromServer -> forceSignOut()
                is ApiResult.Success -> {
                    dataStore.edit { prefs ->

                        prefs[LOCAL_CREDENTIAL_ID] = credentialId
                    }
                    if(result.data == ("ok")) {
                        signInStateMutable.emit(SignInState.CompletedSignIn(username))
                    }
                }
            }
        } catch (e: ApiException) {
            Log.e(TAG, "Cannot call registerResponse", e)
        }
    }

   suspend fun signInToBankUI(username: String){
        signInStateMutable.emit(SignInState.CompletedSignIn(username))
    }

}
