// ================================================================
// AIR QUALITY MONITORING SYSTEM USING DHT11 + MQ SENSOR
// WITH LCD DISPLAY, ARDUINO IoT CLOUD, AND UDP Wi-Fi COMMUNICATION
// ================================================================

#include <LiquidCrystal.h>
#include "DHT.h"
#include <ArduinoIoTCloud.h>
#include <Arduino_ConnectionHandler.h>
#include <ESP8266WiFi.h>
#include <WiFiUdp.h>

// ================= LCD CONNECTIONS =================
// LiquidCrystal(rs, en, d4, d5, d6, d7)
LiquidCrystal lcd(D0, D1, D2, D3, D5, D6);

// ================= DHT SENSOR SETUP =================
#define DHTPIN D7
#define DHTTYPE DHT11
DHT dht(DHTPIN, DHTTYPE);

// ================= GAS SENSOR =================
#define GAS_PIN A0
const int GAS_THRESHOLD = 340;

// ================= IoT CLOUD CREDENTIALS =================
const char DEVICE_LOGIN_NAME[] = "bfc70e50-9b79-4816-b2c7-7cb4364f968b";
const char SSID[] = "projectiot";
const char PASS[] = "projectiot";
const char DEVICE_KEY[] = "YfaSNgCSf!aHUKpzzptRSLdIE";

// ================= CLOUD VARIABLES =================
String status;
int gas;
int humi;
float temp;
String pr;

// ================= UDP CONFIG =================
WiFiUDP udp;
const int udpPort = 4210;                // Same as Python receiver
const char* broadcastIP = "255.255.255.255";  // Broadcast on local network

// ================= FUNCTION DECLARATIONS =================
void onPrChange();
void onTempChange();
void onHumiChange();
void onGasChange();
void onStatusChange();

void initProperties() {
  ArduinoCloud.setBoardId(DEVICE_LOGIN_NAME);
  ArduinoCloud.setSecretDeviceKey(DEVICE_KEY);
  ArduinoCloud.addProperty(pr, READWRITE, ON_CHANGE, onPrChange);
  ArduinoCloud.addProperty(status, READWRITE, ON_CHANGE, onStatusChange);
  ArduinoCloud.addProperty(gas, READWRITE, ON_CHANGE, onGasChange);
  ArduinoCloud.addProperty(humi, READWRITE, ON_CHANGE, onHumiChange);
  ArduinoCloud.addProperty(temp, READWRITE, ON_CHANGE, onTempChange);
}

WiFiConnectionHandler ArduinoIoTPreferredConnection(SSID, PASS);

// ================= SETUP =================
void setup() {
  Serial.begin(115200);
  delay(1500);

  initProperties();
  ArduinoCloud.begin(ArduinoIoTPreferredConnection);
  setDebugMessageLevel(2);
  ArduinoCloud.printDebugInfo();

  // Initialize LCD
  lcd.begin(16, 2);
  lcd.print("Air Quality Mon");
  lcd.setCursor(0, 1);
  lcd.print("Initializing...");
  delay(2000);
  lcd.clear();

  // Initialize DHT sensor
  dht.begin();

  // Start Wi-Fi manually for UDP
  WiFi.begin(SSID, PASS);
  lcd.print("Wi-Fi Connecting");
  int tries = 0;
  while (WiFi.status() != WL_CONNECTED && tries < 25) {
    delay(500);
    tries++;
  }
  lcd.clear();
  if (WiFi.status() == WL_CONNECTED) {
    lcd.print("Wi-Fi Connected");
    delay(1000);
    lcd.clear();
    udp.begin(udpPort);
  } else {
    lcd.print("Wi-Fi Failed!");
    while (1);
  }
}

// ================= LOOP =================
void loop() {
  ArduinoCloud.update();

  float temperature = dht.readTemperature();
  float humidity = dht.readHumidity();
  int gasValue = analogRead(GAS_PIN);

  if (isnan(temperature) || isnan(humidity)) {
    lcd.clear();
    lcd.print("Sensor Error!");
    delay(2000);
    return;
  }

  // Display on LCD
  lcd.clear();
  lcd.setCursor(0, 0);
  lcd.print("T");
  lcd.print(temperature, 1);
  lcd.print((char)223);
  lcd.print("C H");
  lcd.print(humidity, 0);
  lcd.print("%");
  lcd.setCursor(0, 1);
  lcd.print("G");
  lcd.print(gasValue);

  // Assign to Cloud vars
  temp = temperature;
  humi = humidity;
  gas = gasValue;

  // Air quality condition
  if (gasValue > GAS_THRESHOLD) {
    status = "UNSAFE";
    lcd.setCursor(14, 0);
    lcd.print("US");
  } else {
    status = "SAFE";
    lcd.setCursor(14, 0);
    lcd.print("SF");
  }  

  lcd.setCursor(5, 1);
  lcd.print(pr.substring(0, 11)); // Show first 11 chars

  // ====== UDP Wi-Fi Communication ======
  String message = "T" + String(temperature, 1) +
                   "C, H" + String(humidity, 0) +
                   "%, G" + String(gasValue) +
                   ", Status:" + status;

  udp.beginPacket(broadcastIP, udpPort);
  udp.print(message);
  udp.endPacket();

  // ====== Debug on Serial (optional) ======
  Serial.println(message);

  delay(2000);
}

// ================= CLOUD EVENT HANDLERS =================
void onTempChange() {}
void onHumiChange() {}
void onGasChange() {}
void onStatusChange() {}
void onPrChange() {}
