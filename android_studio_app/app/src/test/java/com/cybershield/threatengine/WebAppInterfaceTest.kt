package com.cybershield.threatengine

import android.content.Context
import android.content.SharedPreferences
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Before
import org.junit.Test
import org.mockito.ArgumentMatchers.anyInt
import org.mockito.ArgumentMatchers.anyString
import org.mockito.Mockito.`when`
import org.mockito.Mockito.mock
import org.mockito.Mockito.verify

class WebAppInterfaceTest {

    private lateinit var mockContext: Context
    private lateinit var mockPrefs: SharedPreferences
    private lateinit var mockEditor: SharedPreferences.Editor
    private lateinit var webAppInterface: WebAppInterface

    @Before
    fun setUp() {
        mockContext = mock(Context::class.java)
        mockPrefs = mock(SharedPreferences::class.java)
        mockEditor = mock(SharedPreferences.Editor::class.java)

        `when`(mockContext.getSharedPreferences(anyString(), anyInt())).thenReturn(mockPrefs)
        `when`(mockPrefs.edit()).thenReturn(mockEditor)
        `when`(mockEditor.putString(anyString(), anyString())).thenReturn(mockEditor)

        webAppInterface = WebAppInterface(mockContext)
    }

    @Test
    fun testSaveServerUrl_trimsAndSavesToPrefs() {
        val testUrl = "  https://example.cybershield.io  "
        webAppInterface.saveServerUrl(testUrl)

        verify(mockPrefs).edit()
        verify(mockEditor).putString("custom_server_url", "https://example.cybershield.io")
        verify(mockEditor).apply()
    }

    @Test
    fun testGetSavedServerUrl_returnsStoredUrl() {
        `when`(mockPrefs.getString("custom_server_url", "")).thenReturn("https://engine.cybershield.io")

        val result = webAppInterface.getSavedServerUrl()
        assertEquals("https://engine.cybershield.io", result)
    }

    @Test
    fun testGetDeviceTelemetry_returnsNonNullJsonString() {
        val telemetry = webAppInterface.getDeviceTelemetry()
        assertNotNull(telemetry)
    }
}
