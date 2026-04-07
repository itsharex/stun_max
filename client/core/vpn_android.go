//go:build android

package core

/*
#cgo LDFLAGS: -landroid -llog

#include <jni.h>
#include <android/log.h>
#include <stdlib.h>

#define LOG_TAG "StunMaxVPN"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, LOG_TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, LOG_TAG, __VA_ARGS__)

// GetEnv attaches the current goroutine thread to the JVM and returns a JNIEnv pointer.
static JNIEnv* GetEnv(JavaVM* vm) {
    JNIEnv* env;
    int status = (*vm)->AttachCurrentThread(vm, &env, NULL);
    if (status != 0) {
        LOGE("AttachCurrentThread failed: %d", status);
        return NULL;
    }
    return env;
}

// DetachThread detaches the current thread from the JVM.
static void DetachThread(JavaVM* vm) {
    (*vm)->DetachCurrentThread(vm);
}

// FindClassFromContext finds a class using the application's ClassLoader.
// This is necessary because FindClass from native threads uses the system
// ClassLoader, which doesn't see classes in classes2.dex (multidex).
// The app's ClassLoader (from context.getClassLoader()) sees all dex files.
static jclass FindClassFromContext(JNIEnv* env, jobject context, const char* className) {
    jclass contextClass = (*env)->GetObjectClass(env, context);
    if (!contextClass) return NULL;

    jmethodID getClassLoader = (*env)->GetMethodID(env, contextClass,
        "getClassLoader", "()Ljava/lang/ClassLoader;");
    if (!getClassLoader) {
        (*env)->ExceptionClear(env);
        (*env)->DeleteLocalRef(env, contextClass);
        return NULL;
    }

    jobject classLoader = (*env)->CallObjectMethod(env, context, getClassLoader);
    (*env)->DeleteLocalRef(env, contextClass);
    if (!classLoader) {
        (*env)->ExceptionClear(env);
        return NULL;
    }

    jclass classLoaderClass = (*env)->GetObjectClass(env, classLoader);
    jmethodID loadClass = (*env)->GetMethodID(env, classLoaderClass,
        "loadClass", "(Ljava/lang/String;)Ljava/lang/Class;");
    (*env)->DeleteLocalRef(env, classLoaderClass);
    if (!loadClass) {
        (*env)->ExceptionClear(env);
        (*env)->DeleteLocalRef(env, classLoader);
        return NULL;
    }

    jstring jClassName = (*env)->NewStringUTF(env, className);
    jclass cls = (jclass)(*env)->CallObjectMethod(env, classLoader, loadClass, jClassName);
    (*env)->DeleteLocalRef(env, jClassName);
    (*env)->DeleteLocalRef(env, classLoader);

    if ((*env)->ExceptionCheck(env)) {
        (*env)->ExceptionDescribe(env);
        (*env)->ExceptionClear(env);
        return NULL;
    }

    return cls;
}

// vpnRequestPermission launches VpnPermissionActivity to show the VPN consent dialog.
// Uses a dedicated Activity (not Application context) so the system dialog appears
// reliably on all Android ROMs (Huawei EMUI, Xiaomi MIUI, etc.).
// Returns 0 if permission already granted, 1 if dialog launched, -1 on error.
static int vpnRequestPermission(JNIEnv* env, jobject context) {
    // First check if permission is already granted
    jclass vpnServiceClass = (*env)->FindClass(env, "android/net/VpnService");
    if (!vpnServiceClass) {
        LOGE("FindClass android/net/VpnService failed");
        (*env)->ExceptionClear(env);
        return -1;
    }
    jmethodID prepareMethod = (*env)->GetStaticMethodID(env, vpnServiceClass,
        "prepare", "(Landroid/content/Context;)Landroid/content/Intent;");
    if (!prepareMethod) {
        LOGE("GetStaticMethodID prepare failed");
        (*env)->ExceptionClear(env);
        (*env)->DeleteLocalRef(env, vpnServiceClass);
        return -1;
    }
    jobject prepIntent = (*env)->CallStaticObjectMethod(env, vpnServiceClass, prepareMethod, context);
    if ((*env)->ExceptionCheck(env)) {
        (*env)->ExceptionDescribe(env);
        (*env)->ExceptionClear(env);
        (*env)->DeleteLocalRef(env, vpnServiceClass);
        return -1;
    }
    (*env)->DeleteLocalRef(env, vpnServiceClass);
    if (prepIntent == NULL) {
        LOGI("VPN permission already granted");
        return 0;
    }
    (*env)->DeleteLocalRef(env, prepIntent);

    // Reset the permission flag in VpnPermissionActivity
    jclass permActivityClass = FindClassFromContext(env, context, "com.stunmax.app.VpnPermissionActivity");
    if (!permActivityClass) {
        LOGE("FindClassFromContext VpnPermissionActivity failed — not in APK?");
        (*env)->ExceptionClear(env);
        return -1;
    }
    jmethodID resetMethod = (*env)->GetStaticMethodID(env, permActivityClass, "resetPermission", "()V");
    if (resetMethod) {
        (*env)->CallStaticVoidMethod(env, permActivityClass, resetMethod);
    }

    // Launch VpnPermissionActivity with FLAG_ACTIVITY_NEW_TASK
    jclass intentClass = (*env)->FindClass(env, "android/content/Intent");
    if (!intentClass) {
        LOGE("FindClass Intent failed");
        (*env)->ExceptionClear(env);
        (*env)->DeleteLocalRef(env, permActivityClass);
        return -1;
    }
    jmethodID intentInit = (*env)->GetMethodID(env, intentClass,
        "<init>", "(Landroid/content/Context;Ljava/lang/Class;)V");
    if (!intentInit) {
        LOGE("Intent constructor not found");
        (*env)->ExceptionClear(env);
        (*env)->DeleteLocalRef(env, intentClass);
        (*env)->DeleteLocalRef(env, permActivityClass);
        return -1;
    }
    jobject intent = (*env)->NewObject(env, intentClass, intentInit, context, permActivityClass);
    if (!intent) {
        LOGE("Failed to create Intent for VpnPermissionActivity");
        (*env)->ExceptionClear(env);
        (*env)->DeleteLocalRef(env, intentClass);
        (*env)->DeleteLocalRef(env, permActivityClass);
        return -1;
    }

    // Add FLAG_ACTIVITY_NEW_TASK
    jfieldID flagField = (*env)->GetStaticFieldID(env, intentClass, "FLAG_ACTIVITY_NEW_TASK", "I");
    jint newTaskFlag = (*env)->GetStaticIntField(env, intentClass, flagField);
    jmethodID addFlagsMethod = (*env)->GetMethodID(env, intentClass, "addFlags", "(I)Landroid/content/Intent;");
    (*env)->CallObjectMethod(env, intent, addFlagsMethod, newTaskFlag);

    // Start the activity
    jclass contextClass = (*env)->GetObjectClass(env, context);
    jmethodID startActivityMethod = (*env)->GetMethodID(env, contextClass,
        "startActivity", "(Landroid/content/Intent;)V");
    (*env)->CallVoidMethod(env, context, startActivityMethod, intent);
    if ((*env)->ExceptionCheck(env)) {
        LOGE("startActivity for VpnPermissionActivity failed");
        (*env)->ExceptionDescribe(env);
        (*env)->ExceptionClear(env);
        (*env)->DeleteLocalRef(env, intent);
        (*env)->DeleteLocalRef(env, intentClass);
        (*env)->DeleteLocalRef(env, permActivityClass);
        (*env)->DeleteLocalRef(env, contextClass);
        return -1;
    }

    (*env)->DeleteLocalRef(env, intent);
    (*env)->DeleteLocalRef(env, intentClass);
    (*env)->DeleteLocalRef(env, permActivityClass);
    (*env)->DeleteLocalRef(env, contextClass);
    LOGI("VpnPermissionActivity launched for VPN consent");
    return 1;
}

// vpnCheckPermissionGranted polls VpnPermissionActivity.isPermissionGranted().
// Returns 1 if granted, 0 if not yet, -1 on error.
static int vpnCheckPermissionGranted(JNIEnv* env, jobject context) {
    jclass cls = FindClassFromContext(env, context, "com.stunmax.app.VpnPermissionActivity");
    if (!cls) {
        (*env)->ExceptionClear(env);
        return -1;
    }
    jmethodID method = (*env)->GetStaticMethodID(env, cls, "isPermissionGranted", "()Z");
    if (!method) {
        (*env)->ExceptionClear(env);
        (*env)->DeleteLocalRef(env, cls);
        return -1;
    }
    jboolean granted = (*env)->CallStaticBooleanMethod(env, cls, method);
    (*env)->DeleteLocalRef(env, cls);
    return granted ? 1 : 0;
}

// vpnCheckRequestInProgress checks if a VPN permission request is still in progress.
// Returns 1 if in progress, 0 if done, -1 on error.
static int vpnCheckRequestInProgress(JNIEnv* env, jobject context) {
    jclass cls = FindClassFromContext(env, context, "com.stunmax.app.VpnPermissionActivity");
    if (!cls) {
        (*env)->ExceptionClear(env);
        return -1;
    }
    jmethodID method = (*env)->GetStaticMethodID(env, cls, "isRequestInProgress", "()Z");
    if (!method) {
        (*env)->ExceptionClear(env);
        (*env)->DeleteLocalRef(env, cls);
        return -1;
    }
    jboolean inProgress = (*env)->CallStaticBooleanMethod(env, cls, method);
    (*env)->DeleteLocalRef(env, cls);
    return inProgress ? 1 : 0;
}

// startVpnService starts the StunMaxVpnService via Context.startService().
// This ensures the VpnService instance is alive before we call establishVpn.
static int startVpnService(JNIEnv* env, jobject context) {
    // Get the Context class
    jclass contextClass = (*env)->GetObjectClass(env, context);
    if (!contextClass) {
        LOGE("GetObjectClass for context failed");
        return -1;
    }

    // Find our VpnService class
    jclass vpnServiceClass = FindClassFromContext(env, context, "com.stunmax.app.StunMaxVpnService");
    if (!vpnServiceClass) {
        LOGE("FindClassFromContext com.stunmax.app.StunMaxVpnService failed - not in APK?");
        (*env)->ExceptionClear(env);
        (*env)->DeleteLocalRef(env, contextClass);
        return -1;
    }

    // Create Intent for our VpnService
    jclass intentClass = (*env)->FindClass(env, "android/content/Intent");
    if (!intentClass) {
        LOGE("FindClass android/content/Intent failed");
        (*env)->ExceptionClear(env);
        (*env)->DeleteLocalRef(env, contextClass);
        (*env)->DeleteLocalRef(env, vpnServiceClass);
        return -1;
    }

    jmethodID intentInit = (*env)->GetMethodID(env, intentClass,
        "<init>", "(Landroid/content/Context;Ljava/lang/Class;)V");
    if (!intentInit) {
        LOGE("Intent constructor not found");
        (*env)->ExceptionClear(env);
        (*env)->DeleteLocalRef(env, contextClass);
        (*env)->DeleteLocalRef(env, vpnServiceClass);
        (*env)->DeleteLocalRef(env, intentClass);
        return -1;
    }

    jobject serviceIntent = (*env)->NewObject(env, intentClass, intentInit, context, vpnServiceClass);
    if (!serviceIntent) {
        LOGE("Failed to create service Intent");
        (*env)->ExceptionClear(env);
        (*env)->DeleteLocalRef(env, contextClass);
        (*env)->DeleteLocalRef(env, vpnServiceClass);
        (*env)->DeleteLocalRef(env, intentClass);
        return -1;
    }

    // Call context.startService(intent)
    jmethodID startServiceMethod = (*env)->GetMethodID(env, contextClass,
        "startService", "(Landroid/content/Intent;)Landroid/content/ComponentName;");
    if (!startServiceMethod) {
        LOGE("startService method not found");
        (*env)->ExceptionClear(env);
        (*env)->DeleteLocalRef(env, contextClass);
        (*env)->DeleteLocalRef(env, vpnServiceClass);
        (*env)->DeleteLocalRef(env, intentClass);
        (*env)->DeleteLocalRef(env, serviceIntent);
        return -1;
    }

    jobject result = (*env)->CallObjectMethod(env, context, startServiceMethod, serviceIntent);
    if ((*env)->ExceptionCheck(env)) {
        (*env)->ExceptionDescribe(env);
        (*env)->ExceptionClear(env);
        (*env)->DeleteLocalRef(env, contextClass);
        (*env)->DeleteLocalRef(env, vpnServiceClass);
        (*env)->DeleteLocalRef(env, intentClass);
        (*env)->DeleteLocalRef(env, serviceIntent);
        return -1;
    }

    if (result != NULL) {
        (*env)->DeleteLocalRef(env, result);
    }
    (*env)->DeleteLocalRef(env, contextClass);
    (*env)->DeleteLocalRef(env, vpnServiceClass);
    (*env)->DeleteLocalRef(env, intentClass);
    (*env)->DeleteLocalRef(env, serviceIntent);

    LOGI("VpnService started successfully");
    return 0;
}

// vpnEstablish calls GoBridge.establishVpn() which delegates to the running VpnService.
// Returns TUN fd or -1 on failure.
static int vpnEstablish(JNIEnv* env, jobject context,
    const char* localIP, const char* peerIP, const char* routes, int mtu) {

    if (!env || !context) {
        LOGE("vpnEstablish: env or context is NULL");
        return -1;
    }

    // Create a global ref to protect context from GC during this call
    jobject safeCtx = (*env)->NewGlobalRef(env, context);
    if (!safeCtx) {
        LOGE("vpnEstablish: failed to create global ref for context (dangling?)");
        (*env)->ExceptionClear(env);
        return -1;
    }

    jclass bridgeClass = FindClassFromContext(env, safeCtx, "com.stunmax.app.GoBridge");
    if (!bridgeClass) {
        LOGE("GoBridge class not found in APK (multidex?)");
        (*env)->ExceptionClear(env);
        return -1;
    }

    jmethodID method = (*env)->GetStaticMethodID(env, bridgeClass, "establishVpn",
        "(Ljava/lang/String;Ljava/lang/String;Ljava/lang/String;ILjava/lang/String;)I");
    if (!method) {
        LOGE("GoBridge.establishVpn method not found");
        (*env)->ExceptionClear(env);
        (*env)->DeleteLocalRef(env, bridgeClass);
        return -1;
    }

    jstring jLocalIP = (*env)->NewStringUTF(env, localIP);
    jstring jPeerIP = (*env)->NewStringUTF(env, peerIP);
    jstring jRoutes = (*env)->NewStringUTF(env, routes);
    jstring jDns = (*env)->NewStringUTF(env, "");

    int fd = (*env)->CallStaticIntMethod(env, bridgeClass, method,
        jLocalIP, jPeerIP, jRoutes, mtu, jDns);

    if ((*env)->ExceptionCheck(env)) {
        (*env)->ExceptionDescribe(env);
        (*env)->ExceptionClear(env);
        fd = -1;
    }

    (*env)->DeleteLocalRef(env, jLocalIP);
    (*env)->DeleteLocalRef(env, jPeerIP);
    (*env)->DeleteLocalRef(env, jRoutes);
    (*env)->DeleteLocalRef(env, jDns);
    (*env)->DeleteLocalRef(env, bridgeClass);
    (*env)->DeleteGlobalRef(env, safeCtx);

    return fd;
}

// vpnStop calls GoBridge.stopVpn() to tear down the VPN.
static void vpnStop(JNIEnv* env, jobject context) {
    jclass bridgeClass = FindClassFromContext(env, context, "com.stunmax.app.GoBridge");
    if (!bridgeClass) {
        (*env)->ExceptionClear(env);
        return;
    }
    jmethodID method = (*env)->GetStaticMethodID(env, bridgeClass, "stopVpn", "()V");
    if (!method) {
        (*env)->ExceptionClear(env);
        (*env)->DeleteLocalRef(env, bridgeClass);
        return;
    }
    (*env)->CallStaticVoidMethod(env, bridgeClass, method);
    if ((*env)->ExceptionCheck(env)) {
        (*env)->ExceptionClear(env);
    }
    (*env)->DeleteLocalRef(env, bridgeClass);
    LOGI("VPN stopped via JNI");
}

// vpnProtectSocket calls GoBridge.protectSocket(fd) to bypass VPN routing for a socket.
static int vpnProtectSocket(JNIEnv* env, jobject context, int fd) {
    jclass bridgeClass = FindClassFromContext(env, context, "com.stunmax.app.GoBridge");
    if (!bridgeClass) {
        (*env)->ExceptionClear(env);
        return 0;
    }
    jmethodID method = (*env)->GetStaticMethodID(env, bridgeClass, "protectSocket", "(I)Z");
    if (!method) {
        (*env)->ExceptionClear(env);
        (*env)->DeleteLocalRef(env, bridgeClass);
        return 0;
    }
    jboolean result = (*env)->CallStaticBooleanMethod(env, bridgeClass, method, fd);
    if ((*env)->ExceptionCheck(env)) {
        (*env)->ExceptionClear(env);
        (*env)->DeleteLocalRef(env, bridgeClass);
        return 0;
    }
    (*env)->DeleteLocalRef(env, bridgeClass);
    return result ? 1 : 0;
}
*/
import "C"

import (
	"fmt"
	"log"
	"strings"
	"sync"
	"time"
	"unsafe"

	"gioui.org/app"
)

// pendingVPNConfig holds VPN parameters that are set before createPlatformTun is called.
// This is necessary because createPlatformTun() has no parameters — the Android implementation
// needs IP/route/mtu info to pass to VpnService.Builder via JNI.
var (
	pendingVPNConfig struct {
		localIP string
		peerIP  string
		routes  []string
		mtu     int
		ready   bool
	}
	pendingVPNMu sync.Mutex
)

// SetPendingVPNConfig stores VPN configuration to be used by createPlatformTun on Android.
// Must be called before createPlatformTun().
func SetPendingVPNConfig(localIP, peerIP string, routes []string, mtu int) {
	pendingVPNMu.Lock()
	pendingVPNConfig.localIP = localIP
	pendingVPNConfig.peerIP = peerIP
	pendingVPNConfig.routes = routes
	pendingVPNConfig.mtu = mtu
	pendingVPNConfig.ready = true
	pendingVPNMu.Unlock()
	log.Printf("[VPN-Android] Pending config set: local=%s peer=%s routes=%v mtu=%d",
		localIP, peerIP, routes, mtu)
}

// androidEstablishVPN performs the full VPN establishment via JNI:
// 1. Check VPN permission via VpnService.prepare()
// 2. Start the StunMaxVpnService
// 3. Wait briefly for the service to initialize
// 4. Call GoBridge.establishVpn() which delegates to the service
// Returns the TUN file descriptor or an error.
func androidEstablishVPN(localIP, peerIP, routes string, mtu int) (int, error) {
	javaVM := app.JavaVM()
	if javaVM == 0 {
		return -1, fmt.Errorf("JavaVM not available (not running on Android?)")
	}
	ctx := app.AppContext()
	if ctx == 0 {
		return -1, fmt.Errorf("Android Application context not available")
	}

	vm := (*C.JavaVM)(unsafe.Pointer(javaVM))
	env := C.GetEnv(vm)
	if env == nil {
		return -1, fmt.Errorf("failed to attach thread to JVM")
	}

	context := C.jobject(unsafe.Pointer(ctx))

	// Step 1: Request VPN permission via VpnPermissionActivity
	perm := C.vpnRequestPermission(env, context)
	if perm < 0 {
		C.DetachThread(vm)
		return -1, fmt.Errorf("VPN permission request failed")
	}
	if perm == 1 {
		// VpnPermissionActivity launched — wait for user to approve
		log.Println("[VPN-Android] VpnPermissionActivity launched, waiting for user approval...")
		C.DetachThread(vm)

		// Poll VpnPermissionActivity.isPermissionGranted() until granted or timeout/denied
		granted := false
		for i := 0; i < 60; i++ { // up to 60 seconds for user interaction
			time.Sleep(1 * time.Second)
			env2 := C.GetEnv(vm)
			if env2 == nil {
				continue
			}
			// Check if permission was granted
			result := C.vpnCheckPermissionGranted(env2, context)
			inProgress := C.vpnCheckRequestInProgress(env2, context)
			C.DetachThread(vm)

			if result == 1 {
				granted = true
				log.Println("[VPN-Android] VPN permission granted by user")
				break
			}
			// If the activity finished (not in progress) but permission not granted, user denied
			if inProgress == 0 && result == 0 {
				log.Println("[VPN-Android] VPN permission denied by user")
				break
			}
		}
		if !granted {
			return -1, fmt.Errorf("VPN permission not granted (user denied or timeout)")
		}

		// Wait for VpnPermissionActivity to fully finish and context to stabilize
		log.Println("[VPN-Android] Permission granted, waiting for activity cleanup...")
		time.Sleep(1 * time.Second)

		// Re-attach for subsequent JNI calls
		env = C.GetEnv(vm)
		if env == nil {
			return -1, fmt.Errorf("failed to re-attach thread after VPN permission grant")
		}

		// Re-acquire context — the old jobject ref may be invalid after activity lifecycle
		ctx2 := app.AppContext()
		if ctx2 == 0 {
			C.DetachThread(vm)
			return -1, fmt.Errorf("Android context lost after VPN permission")
		}
		context = C.jobject(unsafe.Pointer(ctx2))
	}
	defer C.DetachThread(vm)

	// Step 2: Start the VpnService
	ret := C.startVpnService(env, context)
	if ret != 0 {
		return -1, fmt.Errorf("failed to start VpnService (is StunMaxVpnService declared in AndroidManifest?)")
	}

	// Step 3: Wait for service onCreate to complete
	time.Sleep(500 * time.Millisecond)

	// Step 4: Establish VPN through GoBridge -> VpnService
	// Re-acquire env and context — startVpnService may have triggered GC
	// or Activity lifecycle changes that invalidate the old jobject refs.
	C.DetachThread(vm)
	env = C.GetEnv(vm)
	if env == nil {
		return -1, fmt.Errorf("failed to re-attach JNI thread before establish")
	}
	freshCtx := app.AppContext()
	if freshCtx == 0 {
		C.DetachThread(vm)
		return -1, fmt.Errorf("Android context lost before establish")
	}
	context = C.jobject(unsafe.Pointer(freshCtx))

	cLocalIP := C.CString(localIP)
	cPeerIP := C.CString(peerIP)
	cRoutes := C.CString(routes)
	defer C.free(unsafe.Pointer(cLocalIP))
	defer C.free(unsafe.Pointer(cPeerIP))
	defer C.free(unsafe.Pointer(cRoutes))

	fd := int(C.vpnEstablish(env, context, cLocalIP, cPeerIP, cRoutes, C.int(mtu)))
	if fd < 0 {
		return -1, fmt.Errorf("VPN establish failed (fd=%d) — check logcat for details", fd)
	}

	log.Printf("[VPN-Android] VPN established successfully, fd=%d", fd)
	return fd, nil
}

// androidStopVPN tears down the VPN via JNI.
func androidStopVPN() {
	javaVM := app.JavaVM()
	if javaVM == 0 {
		return
	}
	ctx := app.AppContext()
	if ctx == 0 {
		return
	}

	vm := (*C.JavaVM)(unsafe.Pointer(javaVM))
	env := C.GetEnv(vm)
	if env == nil {
		return
	}
	defer C.DetachThread(vm)

	context := C.jobject(unsafe.Pointer(ctx))
	C.vpnStop(env, context)
	log.Println("[VPN-Android] VPN stopped")
}

// AndroidProtectSocket protects a socket fd from being routed through the VPN.
// This should be called for the signaling WebSocket to prevent routing loops.
func AndroidProtectSocket(fd int) bool {
	javaVM := app.JavaVM()
	if javaVM == 0 {
		return false
	}
	ctx := app.AppContext()
	if ctx == 0 {
		return false
	}

	vm := (*C.JavaVM)(unsafe.Pointer(javaVM))
	env := C.GetEnv(vm)
	if env == nil {
		return false
	}
	defer C.DetachThread(vm)

	context := C.jobject(unsafe.Pointer(ctx))
	return C.vpnProtectSocket(env, context, C.int(fd)) == 1
}

// androidCreatePlatformTun is called from createPlatformTun (in tun_config_android.go)
// to establish the VPN via JNI using the pending config.
func androidCreatePlatformTun() (int, error) {
	pendingVPNMu.Lock()
	cfg := pendingVPNConfig
	pendingVPNMu.Unlock()

	if !cfg.ready {
		return -1, fmt.Errorf("Android VPN config not set — call SetPendingVPNConfig first")
	}

	routeStr := strings.Join(cfg.routes, ",")
	mtu := cfg.mtu
	if mtu <= 0 {
		mtu = 1400
	}

	return androidEstablishVPN(cfg.localIP, cfg.peerIP, routeStr, mtu)
}
