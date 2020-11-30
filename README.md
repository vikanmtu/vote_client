# vote_client
Client APP for secure voting

Secure e-Voting Client

The voting Client provides a secret vote and communicates with the server through the Tor network. Voting stages:
- scanning QR-code of a personal invitation to the elections;
- anonimous request the public key from onion-address specified server (end-to-end protected by Tor);
- personal authentication and registration;
- get anonymous ballot;
- voting (selection of a candidate and sending a closed ballot back to server);
- receiving a ticket (signature of closed voice) from the server and disclosing a voice;

Scaning of QR-code can switch Front/Back camera, set resolution and light. 
Alternatively instead of scan QR code you can use a binary file provided to the user as an invitation or enter the necessary data 

manually:
- onion-address of the server;
- number of the client in the voter list:
- his password;

Personal identification and registration implies identity disclosure  so after this stages you must exit from app and continue anonymous 
voting later. In this case, the Tor will be restarted and change your network identity and the time difference will prevent a possible 
attack on the disclosure of identity by the connection time.

All network transactions with the server have signatures and are saved on the local device: in the 'pub' subfolder in the application 
working folder in Windows and in the Android folder 'Documens' -> 'vote'. With these tickets you can prove the fact of fraud by the 
Registrar or the Recorder during the voting.

Client source code writed on C (core) and C++ (GUI). Embarcadero RAD studio provides crossplatform build for Windows or Android 
platform.  Windows app is fully portable  and compatible with 32 bit XP up to 64 bit Win10. Android app is compatible with 32 and 54 bit 
ARM devices and Android 4.1 and highter.

Permitions (from manifest):
    <uses-sdk android:minSdkVersion="14" android:targetSdkVersion="14" />    
    <uses-permission android:name="android.permission.CAMERA" />
    <uses-permission android:name="android.permission.INTERNET" />
    <uses-permission android:name="android.permission.READ_EXTERNAL_STORAGE" />
    <uses-permission android:name="android.permission.WRITE_EXTERNAL_STORAGE" />
Uses toolchain:
    Embarcadero® RAD Studio 10.2 Version 25.0.26309.314     
    Android SDK 24.3.3  API: android-22
    android-ndk-r9c API: android-14
    jdk1.8.0_60

Included Tor is prebuild binary deployed in apk, see:
https://github.com/guardianproject/tor-android

Developer: Viktoria Malevanchenko, student of NMTU named acad.Yu.Bugai, Ukraine, Poltava, 2020

MaitTo: vika_nmtu@protonmail.com
