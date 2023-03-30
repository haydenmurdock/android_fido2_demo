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

package com.presidioIdentityDemo.fido2.ui.home

import android.app.Activity
import android.os.Bundle
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import android.widget.Toast
import androidx.activity.result.ActivityResult
import androidx.activity.result.IntentSenderRequest
import androidx.activity.result.contract.ActivityResultContracts
import androidx.fragment.app.Fragment
import androidx.fragment.app.viewModels
import androidx.lifecycle.lifecycleScope
import com.example.fido2.R
import com.presidioIdentityDemo.fido2.api.DataHolder
import com.example.fido2.databinding.HomeFragmentBinding
import com.google.android.gms.fido.Fido
import com.google.android.gms.fido.fido2.api.common.AuthenticatorErrorResponse
import com.google.android.gms.fido.fido2.api.common.PublicKeyCredential
import com.google.android.gms.fido.fido2.api.common.PublicKeyCredentialCreationOptions
import dagger.hilt.android.AndroidEntryPoint
import kotlinx.coroutines.flow.collect
import kotlinx.coroutines.launch

@AndroidEntryPoint
class HomeFragment : Fragment(), DeleteConfirmationFragment.Listener {


    private val viewModel: HomeViewModel by viewModels()
    private lateinit var binding: HomeFragmentBinding
    private var publicKeyCredentialCreationOptions: PublicKeyCredentialCreationOptions? = null

    private val createCredentialIntentLauncher = registerForActivityResult(
        ActivityResultContracts.StartIntentSenderForResult(),
        ::handleCreateCredentialResult
    )

    override fun onCreateView(
        inflater: LayoutInflater,
        container: ViewGroup?, savedInstanceState: Bundle?
    ): View? {
        binding = HomeFragmentBinding.inflate(inflater, container, false)
        binding.lifecycleOwner = viewLifecycleOwner
        binding.viewModel = viewModel
        return binding.root
    }

    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {

       publicKeyCredentialCreationOptions = DataHolder.getPkcco()

        viewLifecycleOwner.lifecycleScope.launchWhenStarted {
        }

        binding.appBar.replaceMenu(R.menu.home)
        binding.appBar.setOnMenuItemClickListener { item ->
            when (item.itemId) {
                R.id.action_sign_out -> {
                    viewModel.signOut()
                    true
                }
                else -> false
            }
        }

        viewLifecycleOwner.lifecycleScope.launchWhenStarted {
            viewModel.processing.collect { processing ->
                if (processing) {
                    binding.processing.show()
                } else {
                    binding.processing.hide()
                }
            }
        }


        binding.add.setOnClickListener {
            lifecycleScope.launch {
                if(!publicKeyCredentialCreationOptions?.equals(null)!!){
                    val intent = viewModel.registerPIRequest(publicKeyCredentialCreationOptions!!)
                    if (intent != null) {
                        createCredentialIntentLauncher.launch(
                            IntentSenderRequest.Builder(intent).build()
                        )
                    }
                }
            }
        }
    }

    private fun handleCreateCredentialResult(activityResult: ActivityResult) {

        // TODO(3): Receive ActivityResult with the new Credential
        // - Extract byte array from result data using Fido.FIDO2_KEY_CREDENTIAL_EXTRA.
        // (continued below
        val bytes = activityResult.data?.getByteArrayExtra(Fido.FIDO2_KEY_CREDENTIAL_EXTRA)
        when {
            activityResult.resultCode != Activity.RESULT_OK ->
                Toast.makeText(requireContext(), R.string.cancelled, Toast.LENGTH_LONG).show()
            bytes == null ->
                Toast.makeText(requireContext(), R.string.credential_error, Toast.LENGTH_LONG)
                    .show()
            else -> {
                val credential = PublicKeyCredential.deserializeFromBytes(bytes)
                val response = credential.response
                if (response is AuthenticatorErrorResponse) {
                    Toast.makeText(requireContext(), response.errorMessage, Toast.LENGTH_LONG)
                        .show()
                } else {
                    viewModel.registerResponse(credential)
                }
            }
        }

    }

    override fun onDeleteConfirmed(credentialId: String) {

    }
}
