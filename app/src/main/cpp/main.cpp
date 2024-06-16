#include <android/log.h>
#include <sys/system_properties.h>
#include <string>
#include <vector>
#include <unistd.h>
#include "zygisk.hpp"

#define LOGD(...) __android_log_print(ANDROID_LOG_DEBUG, "PIF", __VA_ARGS__)

#define CLASSES_DEX "/data/adb/modules/keystoreinjection/classes.dex"

#define KEYBOX_FILE_PATH "/data/adb/keybox.xml"

ssize_t xread(int fd, void *buffer, size_t count) {
    ssize_t total = 0;
    char *buf = (char *)buffer;
    while (count > 0) {
        ssize_t ret = read(fd, buf, count);
        if (ret < 0) return -1;
        buf += ret;
        total += ret;
        count -= ret;
    }
    return total;
}

ssize_t xwrite(int fd, void *buffer, size_t count) {
    ssize_t total = 0;
    char *buf = (char *)buffer;
    while (count > 0) {
        ssize_t ret = write(fd, buf, count);
        if (ret < 0) return -1;
        buf += ret;
        total += ret;
        count -= ret;
    }
    return total;
}

class KeystoreInjection : public zygisk::ModuleBase {
public:
    void onLoad(zygisk::Api *api, JNIEnv *env) override {
        this->api = api;
        this->env = env;
    }

    void preAppSpecialize(zygisk::AppSpecializeArgs *args) override {
        // Dex will be copied in memory so we can close module itself
        api->setOption(zygisk::DLCLOSE_MODULE_LIBRARY);

        if (!args) return;

        const char *rawDir = env->GetStringUTFChars(args->app_data_dir, nullptr);
        if (!rawDir) return;

        std::string dir(rawDir);
        env->ReleaseStringUTFChars(args->app_data_dir, rawDir);
        if (!dir.ends_with("/io.github.vvb2060.keyattestation")) {
            return;
        }

        long dexSize = 0, xmlSize = 0;

        int fd = api->connectCompanion();

        xread(fd, &dexSize, sizeof(long));
        xread(fd, &xmlSize, sizeof(long));

        LOGD("Dex file size: %ld", dexSize);
        LOGD("Xml file size: %ld", xmlSize);

        if (dexSize < 1 || xmlSize < 1) {
            close(fd);
            return;
        }

        dexVector.resize(dexSize);
        xread(fd, dexVector.data(), dexSize);

        std::vector<uint8_t> xmlVector;
        xmlVector.resize(xmlSize);
        xread(fd, xmlVector.data(), xmlSize);

        close(fd);

        std::string xmlString(xmlVector.begin(), xmlVector.end());
        xml = xmlString;
    }

    void postAppSpecialize(const zygisk::AppSpecializeArgs *args) override {
        if (dexVector.empty() || xml.empty()) return;
        injectDex();
    }

    void preServerSpecialize(zygisk::ServerSpecializeArgs *args) override {
        api->setOption(zygisk::DLCLOSE_MODULE_LIBRARY);
    }

private:
    zygisk::Api *api = nullptr;
    JNIEnv *env = nullptr;
    std::vector<uint8_t> dexVector;
    std::string xml;

    void injectDex() {
        LOGD("get system classloader");
        auto clClass = env->FindClass("java/lang/ClassLoader");
        auto getSystemClassLoader = env->GetStaticMethodID(clClass, "getSystemClassLoader",
                                                           "()Ljava/lang/ClassLoader;");
        auto systemClassLoader = env->CallStaticObjectMethod(clClass, getSystemClassLoader);

        LOGD("create class loader");
        auto dexClClass = env->FindClass("dalvik/system/InMemoryDexClassLoader");
        auto dexClInit = env->GetMethodID(dexClClass, "<init>",
                                          "(Ljava/nio/ByteBuffer;Ljava/lang/ClassLoader;)V");
        auto buffer = env->NewDirectByteBuffer(dexVector.data(), dexVector.size());
        auto dexCl = env->NewObject(dexClClass, dexClInit, buffer, systemClassLoader);

        LOGD("load class");
        auto loadClass = env->GetMethodID(clClass, "loadClass",
                                          "(Ljava/lang/String;)Ljava/lang/Class;");
        auto entryClassName = env->NewStringUTF("io.github.aviraxp.keystoreinjection.EntryPoint");
        auto entryClassObj = env->CallObjectMethod(dexCl, loadClass, entryClassName);

        auto entryPointClass = (jclass) entryClassObj;

        LOGD("receive xml");
        auto receiveXml = env->GetStaticMethodID(entryPointClass, "receiveXml", "(Ljava/lang/String;)V");
        auto xmlString = env->NewStringUTF(xml.c_str());
        env->CallStaticVoidMethod(entryPointClass, receiveXml, xmlString);
    }
};

static std::vector<uint8_t> readFile(const char *path) {

    std::vector<uint8_t> vector;

    FILE *file = fopen(path, "rb");

    if (file) {
        fseek(file, 0, SEEK_END);
        long size = ftell(file);
        fseek(file, 0, SEEK_SET);

        vector.resize(size);
        fread(vector.data(), 1, size, file);
        fclose(file);
    } else {
        LOGD("Couldn't read %s file!", path);
    }

    return vector;
}

static void companion(int fd) {

    std::vector<uint8_t> dexVector, xmlVector;

    dexVector = readFile(CLASSES_DEX);
    xmlVector = readFile(KEYBOX_FILE_PATH);

    long dexSize = dexVector.size();
    long xmlSize = xmlVector.size();

    xwrite(fd, &dexSize, sizeof(long));
    xwrite(fd, &xmlSize, sizeof(long));

    xwrite(fd, dexVector.data(), dexSize);
    xwrite(fd, xmlVector.data(), xmlSize);
}

REGISTER_ZYGISK_MODULE(KeystoreInjection)

REGISTER_ZYGISK_COMPANION(companion)