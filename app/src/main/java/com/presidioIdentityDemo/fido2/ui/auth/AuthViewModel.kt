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

package com.presidioIdentityDemo.fido2.ui.auth

import android.app.PendingIntent
import androidx.lifecycle.ViewModel
import androidx.lifecycle.viewModelScope
import com.presidioIdentityDemo.fido2.repository.AuthRepository
import com.presidioIdentityDemo.fido2.repository.SignInState
import com.google.android.gms.fido.fido2.api.common.PublicKeyCredential
import dagger.hilt.android.lifecycle.HiltViewModel
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.combine
import kotlinx.coroutines.flow.map
import kotlinx.coroutines.flow.receiveAsFlow
import kotlinx.coroutines.flow.stateIn
import kotlinx.coroutines.launch
import javax.inject.Inject

@HiltViewModel
class AuthViewModel @Inject constructor(
    private val repository: AuthRepository
) : ViewModel() {

    val password = MutableStateFlow("")

    private val _processing = MutableStateFlow(false)
    val processing = _processing.asStateFlow()

    private val _errorMessage = MutableStateFlow<String?>(null)
    val errorMessage = _errorMessage.asStateFlow()

    val signInEnabled = combine(processing, password) { isProcessing, password ->
        !isProcessing && password.isNotBlank()
    }.stateIn(viewModelScope, SharingStarted.Eagerly, false)

    private val signinRequestChannel = Channel<PendingIntent>(capacity = Channel.CONFLATED)
    val signInRequests = signinRequestChannel.receiveAsFlow()


    val currentUsername = repository.signInState.map { state ->
        when (state) {
            is SignInState.SigningIn -> state.username
            is SignInState.SignedIn -> state.username
            is SignInState.CompletedSignIn -> state.username
            else -> {}
        }
    }.stateIn(viewModelScope, SharingStarted.WhileSubscribed(), false)

    suspend fun signIn(){
        val intent = repository.signInRequest(currentUsername.value.toString())
        if (intent != null) {
            signinRequestChannel.send(intent)
        }
    }

    fun submitPassword() {
        viewModelScope.launch {
            repository.password(currentUsername.value.toString())
            _processing.value = true
            try {
            } finally {
                _processing.value = false
            }
        }
    }

    fun signInResponse(credential: PublicKeyCredential) {
        viewModelScope.launch {
            _processing.value = true
            try {
                repository.signinResponse(credential)
                signInToBankUI(currentUsername.value.toString())
            } finally {
                _processing.value = false
            }
        }
    }

    private fun signInToBankUI(username: String){
        viewModelScope.launch{
            _processing.value = true
            try {
                repository.signInToBankUI(username)
            } finally {
                _processing.value = false
            }
        }
    }

     fun userNameVerified() {
         viewModelScope.launch {
             try {
                 // repository.userNameHasBeenVerified()
             } finally {

             }
         }
     }

}
