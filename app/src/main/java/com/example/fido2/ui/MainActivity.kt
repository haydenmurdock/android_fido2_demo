package com.example.fido2.ui

import android.os.Bundle
import android.os.StrictMode
import android.widget.Toast
import androidx.activity.viewModels
import androidx.appcompat.app.AppCompatActivity
import androidx.fragment.app.Fragment
import androidx.fragment.app.commit
import androidx.lifecycle.lifecycleScope
import com.example.fido2.Fido2App
import com.example.fido2.repository.SignInState
import com.example.fido2.ui.auth.AuthFragment
import com.example.fido2.ui.home.HomeFragment
import com.example.fido2.ui.username.UsernameFragment
import com.example.fido2.R
import com.example.fido2.ui.bank.BankAccountFragment
import com.google.android.gms.fido.Fido
import dagger.hilt.android.AndroidEntryPoint
import kotlinx.coroutines.flow.collect

@AndroidEntryPoint
class MainActivity : AppCompatActivity() {

    private val viewModel: MainViewModel by viewModels()
    var credentialsExist = false

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.main_activity)
        setSupportActionBar(findViewById(R.id.toolbar))
        supportActionBar?.hide()
        val policy = StrictMode.ThreadPolicy.Builder()
            .permitAll().build()
        StrictMode.setThreadPolicy(policy)

        lifecycleScope.launchWhenStarted {
            viewModel.signInState.collect { state ->
                when (state) {

                    is SignInState.SignedOut -> {
                        println(state)
                        showFragment(UsernameFragment::class.java) { UsernameFragment() }
                    }
                    is SignInState.SigningIn -> {
                        println(state)
                        showFragment(AuthFragment::class.java) { AuthFragment() }
                    }
                    is SignInState.SignInError -> {
                        println(state)
                        Toast.makeText(this@MainActivity, state.error, Toast.LENGTH_LONG).show()
                        // return to username prompt
                        showFragment(UsernameFragment::class.java) { UsernameFragment() }
                    }
                    is SignInState.CompletedSignIn ->{
                        println(state)
                        showFragment(BankAccountFragment::class.java) { BankAccountFragment() }
                    }
                    is SignInState.SignedIn -> {
                        println(state)
                            showFragment(HomeFragment::class.java) { HomeFragment() }
                        }
                    }
                }
            }
        }

    private fun showFragment(clazz: Class<out Fragment>, create: () -> Fragment) {
        val manager = supportFragmentManager
        if (!clazz.isInstance(manager.findFragmentById(R.id.container))) {
            manager.commit {
                replace(R.id.container, create())
            }
        } else {
            println("could not find is class ")
        }
    }

    override fun onResume() {
        super.onResume()
        viewModel.setFido2ApiClient(Fido.getFido2ApiClient(this))
    }

    override fun onPause() {
        super.onPause()
        viewModel.setFido2ApiClient(null)
    }

    override fun onDestroy() {
        viewModel.signOut()
        super.onDestroy()
    }
}