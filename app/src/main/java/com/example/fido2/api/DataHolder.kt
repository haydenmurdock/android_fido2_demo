package com.example.fido2.api

import com.google.android.gms.fido.fido2.api.common.PublicKeyCredentialCreationOptions

// This will hold all of the publicKeyApiObjects
object DataHolder {

    private var pkcco: PublicKeyCredentialCreationOptions? = null

    fun setPkcco(mPkcco: PublicKeyCredentialCreationOptions){
        pkcco = mPkcco
    }

    fun getPkcco():PublicKeyCredentialCreationOptions? {
        return pkcco
    }
}