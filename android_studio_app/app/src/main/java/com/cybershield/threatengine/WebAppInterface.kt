package com.cybershield.threatengine

import android.content.Context
import android.content.Intent
import android.net.ConnectivityManager
import android.net.NetworkCapabilities
import android.net.Uri
import android.os.Build
import android.os.VibrationEffect
import android.os.Vibrator
import android.os.VibratorManager
import android.webkit.JavascriptInterface
import android.widget.Toast
import org.json.JSONObject

/**
 * JavaScript Interface exposing native Android device capabilities
 * to the CYBERSHIELD HTML/JS client.
 */
class WebAppInterface(private val context: Context) {

    private val prefs = context.getSharedPreferences("cybershield_prefs", Context.MODE_PRIVATE)

    @JavascriptInterface
    fun showToast(message: String) {
        Toast.makeText(context, message, Toast.LENGTH_SHORT).show()
    }

    @JavascriptInterface
    fun triggerHaptic(severity: String) {
        try {
            val vibrator = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
                val manager = context.getSystemService(Context.VIBRATOR_MANAGER_SERVICE) as? VibratorManager
                manager?.defaultVibrator
            } else {
                @Suppress("DEPRECATION")
                context.getSystemService(Context.VIBRATOR_SERVICE) as? Vibrator
            }

            if (vibrator != null && vibrator.hasVibrator()) {
                val durationMs = when (severity.uppercase()) {
                    "CRITICAL" -> 250L
                    "HIGH" -> 120L
                    else -> 40L
                }
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                    val amplitude = if (severity.uppercase() == "CRITICAL") 255 else 180
                    vibrator.vibrate(VibrationEffect.createOneShot(durationMs, amplitude))
                } else {
                    @Suppress("DEPRECATION")
                    vibrator.vibrate(durationMs)
                }
            }
        } catch (e: Exception) {
            e.printStackTrace()
        }
    }

    @JavascriptInterface
    fun getDeviceTelemetry(): String {
        val json = JSONObject()
        json.put("platform", "Android")
        json.put("os_version", Build.VERSION.RELEASE)
        json.put("sdk_int", Build.VERSION.SDK_INT)
        json.put("device_model", "${Build.MANUFACTURER} ${Build.MODEL}")
        json.put("network_type", getActiveNetworkType())
        json.put("saved_server", getSavedServerUrl())
        return json.toString()
    }

    @JavascriptInterface
    fun saveServerUrl(url: String) {
        prefs.edit().putString("custom_server_url", url.trim()).apply()
    }

    @JavascriptInterface
    fun getSavedServerUrl(): String {
        return prefs.getString("custom_server_url", "") ?: ""
    }

    @JavascriptInterface
    fun openExternalLink(url: String) {
        try {
            val intent = Intent(Intent.ACTION_VIEW, Uri.parse(url))
            intent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK)
            context.startActivity(intent)
        } catch (e: Exception) {
            showToast("Cannot open URL: $url")
        }
    }

    private fun getActiveNetworkType(): String {
        val cm = context.getSystemService(Context.CONNECTIVITY_SERVICE) as? ConnectivityManager ?: return "UNKNOWN"
        val network = cm.activeNetwork ?: return "DISCONNECTED"
        val caps = cm.getNetworkCapabilities(network) ?: return "DISCONNECTED"
        return when {
            caps.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) -> "WIFI"
            caps.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR) -> "CELLULAR"
            caps.hasTransport(NetworkCapabilities.TRANSPORT_ETHERNET) -> "ETHERNET"
            else -> "CONNECTED"
        }
    }
}
