package com.presidioIdentityDemo.fido2.ui.bank

import android.os.Bundle
import androidx.fragment.app.Fragment
import android.view.LayoutInflater
import android.view.View
import android.view.ViewGroup
import androidx.fragment.app.viewModels
import com.example.fido2.databinding.FragmentBankAccountBinding
import dagger.hilt.android.AndroidEntryPoint

@AndroidEntryPoint
class BankAccountFragment : Fragment() {

    private val viewModel: BankAccountViewModel by viewModels()
    private lateinit var binding: FragmentBankAccountBinding

    override fun onCreateView(
        inflater: LayoutInflater,
        container: ViewGroup?,
        savedInstanceState: Bundle?
    ): View? {
        binding = FragmentBankAccountBinding.inflate(inflater, container, false)
        binding.lifecycleOwner = viewLifecycleOwner
        binding.viewModel = viewModel
        return binding.root
    }

    override fun onViewCreated(view: View, savedInstanceState: Bundle?) {

        binding.signoutBtnBankAccount.setOnClickListener{
            viewModel.signOut()
        }
    }

}