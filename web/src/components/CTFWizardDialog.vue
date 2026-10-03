<template>
  <v-dialog
    v-model="visible"
    width="640"
    @keydown.enter.prevent="submitCurrent"
  >
    <v-card>
      <v-card-title>
        <span class="text-h5">CTF Setup Wizards</span>
      </v-card-title>
      <v-tabs v-model="tab" stacked color="primary">
        <v-tab value="tab_flag_regex">
          Setup Flag tags
          <v-icon>mdi-flag</v-icon>
        </v-tab>
        <v-tab value="tab_service_by_port">
          Setup Service ports
          <v-icon>mdi-cloud-outline</v-icon>
        </v-tab>
        <v-tab value="tab_attack_flags">
          Attack flag IDs
          <v-icon>mdi-flag-variant</v-icon>
        </v-tab>
      </v-tabs>
      <v-tabs-window v-model="tab">
        <v-tabs-window-item value="tab_service_by_port">
          <v-form>
            <v-card-text>
              This wizard will create a service with the given port(s). Enter
              the ports separated by commas, ranges using a dash.

              <v-text-field
                v-model="serviceName"
                label="Service name"
                autofocus
                :rules="[() => serviceName != '']"
              ></v-text-field>
              <v-text-field
                v-model="servicePorts"
                label="Service ports"
                example="80,8080-8081"
                :rules="[() => goodServicePorts]"
              ></v-text-field>
            </v-card-text>
            <v-card-actions>
              <v-spacer></v-spacer>
              <v-btn variant="text" @click="visible = false">Cancel</v-btn>
              <v-btn
                variant="text"
                :disabled="
                  serviceName == '' ||
                  !goodServicePorts ||
                  service_by_port_loading
                "
                :loading="service_by_port_loading"
                :color="service_by_port_error ? 'error' : 'primary'"
                type="submit"
                @click="createService"
                >Create Service</v-btn
              >
            </v-card-actions>
          </v-form>
        </v-tabs-window-item>
        <v-tabs-window-item value="tab_flag_regex">
          <v-form>
            <v-card-text>
              This wizard will create the two tags {{ flagInName }} and
              {{ flagOutName }} with the specified regex below if they don't
              already exist.

              <v-text-field
                v-model="flagRegex"
                label="Flag Regex"
                example="flag_[a-fA-F0-9]{32}"
                autofocus
                :rules="[() => goodFlagRegex]"
              ></v-text-field>
            </v-card-text>
            <v-card-actions>
              <v-spacer></v-spacer>
              <v-btn variant="text" @click="visible = false">Cancel</v-btn>
              <v-btn
                variant="text"
                :disabled="!goodFlagRegex || flag_regex_loading"
                :loading="flag_regex_loading"
                :color="flag_regex_error ? 'error' : 'primary'"
                type="submit"
                @click="createFlagTags"
                >Create Flag tags</v-btn
              >
            </v-card-actions>
          </v-form>
        </v-tabs-window-item>
        <v-tabs-window-item value="tab_attack_flags">
          <v-form>
            <v-card-text>
              Mark flag IDs from a changing attack.json feed in packet data and
              make matching streams searchable with the flag_id tag. Clear the
              URL and save to disable it. These settings apply to all users
              immediately.
              <v-text-field
                v-model="attackURL"
                :disabled="attackLoading"
                class="mt-4"
                label="Attack JSON URL"
                placeholder="https://example.org/attack.json"
                :rules="[() => goodAttackURL || 'Enter an HTTP or HTTPS URL']"
              ></v-text-field>
              <v-text-field
                v-model="attackPath"
                :disabled="attackLoading"
                label="Flag ID JSON path"
                placeholder="services.*.flag_ids"
                hint="Dot-separated keys; * traverses arrays or objects. The default also accepts top-level attack_info."
                persistent-hint
                :rules="[() => goodAttackPath || 'Enter a valid JSON path']"
              ></v-text-field>
              <v-text-field
                v-model="attackTickDuration"
                :disabled="attackLoading"
                label="Tick duration"
                placeholder="2m"
                hint="Go duration, for example 30s, 2m, or 1h"
                persistent-hint
                :rules="[
                  () => goodAttackTickDuration || 'Enter a duration such as 2m',
                ]"
              ></v-text-field>
            </v-card-text>
            <v-card-actions>
              <v-spacer></v-spacer>
              <v-btn variant="text" @click="visible = false">Close</v-btn>
              <v-btn
                variant="text"
                :disabled="
                  !goodAttackURL ||
                  !goodAttackPath ||
                  !goodAttackTickDuration ||
                  attackLoading
                "
                :loading="attackLoading"
                :color="attackError ? 'error' : 'primary'"
                type="button"
                @click="saveAttackFlags"
                >Save attack feed</v-btn
              >
            </v-card-actions>
          </v-form>
        </v-tabs-window-item>
      </v-tabs-window>
    </v-card>
  </v-dialog>
</template>

<script lang="ts" setup>
import { EventBus } from "./EventBus";
import { ref, computed } from "vue";
import { useRootStore } from "@/stores";
import { randomColor } from "@/lib/colors";
import APIClient from "@/apiClient";
import axios from "axios";

const store = useRootStore();
const visible = ref(false);
const tab = ref("");

const flag_regex_loading = ref(false);
const flag_regex_error = ref(false);
const flagRegex = ref("");
const attackURL = ref("");
const attackPath = ref("flag_ids");
const attackTickDuration = ref("2m");
const attackLoading = ref(false);
const attackError = ref(false);

const service_by_port_loading = ref(false);
const service_by_port_error = ref(false);
const serviceName = ref("");
const servicePorts = ref("");

const tagPrefix = "tag/";
const servicePrefix = "service/";
const flagInName = "flag_in";
const flagInColor = "#66ff66";
const flagInPrefix = "cdata:";
const flagOutName = "flag_out";
const flagOutColor = "#ff6666";
const flagOutPrefix = "sdata:";

EventBus.on("showCTFWizard", openDialog);

const goodServicePorts = computed(() => {
  return /^( *, *[0-9]+ *([-:] *[0-9]+ *)?)+$/.test("," + servicePorts.value);
});

const goodFlagRegex = computed(() => {
  const v = flagRegex.value;
  if (v === "" || v.includes(" ")) return false;
  try {
    RegExp(v);
  } catch {
    return false;
  }
  return true;
});

const goodAttackURL = computed(() => {
  if (attackURL.value === "") return true;
  try {
    const url = new URL(attackURL.value);
    return url.protocol === "http:" || url.protocol === "https:";
  } catch {
    return false;
  }
});
const goodAttackPath = computed(
  () => attackPath.value !== "" && attackPath.value.split(".").every(Boolean),
);
const goodAttackTickDuration = computed(() =>
  /^(?:\d+(?:\.\d+)?(?:ns|us|µs|ms|s|m|h))+$/.test(attackTickDuration.value),
);

function openDialog() {
  visible.value = true;
  tab.value = "tab_flag_regex";

  flag_regex_loading.value = false;
  flag_regex_error.value = false;

  service_by_port_loading.value = false;
  service_by_port_error.value = false;
  attackLoading.value = true;
  attackError.value = false;
  APIClient.getAttackFlagSettings()
    .then((settings) => {
      attackURL.value = settings.URL;
      attackPath.value = settings.Path;
      attackTickDuration.value = settings.TickDuration;
    })
    .catch((err: unknown) => EventBus.emit("showError", errorMessage(err)))
    .finally(() => {
      attackLoading.value = false;
    });
}

function submitCurrent() {
  switch (tab.value) {
    case "tab_flag_regex":
      createFlagTags();
      break;
    case "tab_service_by_port":
      createService();
      break;
    case "tab_attack_flags":
      void saveAttackFlags();
      break;
  }
}

function errorMessage(err: unknown) {
  if (axios.isAxiosError<string>(err)) {
    return typeof err.response?.data === "string"
      ? err.response.data
      : err.message;
  }
  return err instanceof Error ? err.message : String(err);
}

async function saveAttackFlags() {
  if (
    attackLoading.value ||
    !goodAttackURL.value ||
    !goodAttackPath.value ||
    !goodAttackTickDuration.value
  )
    return;
  attackLoading.value = true;
  attackError.value = false;
  try {
    const settings = await APIClient.updateAttackFlagSettings({
      URL: attackURL.value,
      Path: attackPath.value,
      TickDuration: attackTickDuration.value,
    });
    attackURL.value = settings.URL;
    attackPath.value = settings.Path;
    attackTickDuration.value = settings.TickDuration;
    EventBus.emit("showMessage", "Attack flag feed settings saved.");
  } catch (err) {
    attackError.value = true;
    EventBus.emit("showError", errorMessage(err));
  } finally {
    attackLoading.value = false;
  }
}

function createService() {
  service_by_port_loading.value = true;
  service_by_port_error.value = false;
  const query = `sport:${servicePorts.value
    .replaceAll("-", ":")
    .replaceAll(" ", "")}`;
  store
    .addTag(servicePrefix + serviceName.value, query, randomColor())
    .then(() => {
      service_by_port_loading.value = false;
      EventBus.emit("showMessage", `Service ${serviceName.value} created.`);
    })
    .catch((err: Error) => {
      service_by_port_error.value = true;
      service_by_port_loading.value = false;
      EventBus.emit("showError", err.message);
    });
}

function createFlagTags() {
  flag_regex_loading.value = true;
  flag_regex_error.value = false;
  Promise.allSettled([
    store.addTag(
      tagPrefix + flagInName,
      flagInPrefix + flagRegex.value,
      flagInColor,
    ),
    store.addTag(
      tagPrefix + flagOutName,
      flagOutPrefix + flagRegex.value,
      flagOutColor,
    ),
  ])
    .then((res) => {
      const rejected = res.filter((r) => r.status === "rejected");
      if (rejected.length != 0) {
        throw new Error(rejected.map((r) => r.reason as string).join("; "));
      }
      visible.value = false;
      flag_regex_loading.value = false;
    })
    .catch((err: Error) => {
      flag_regex_error.value = true;
      flag_regex_loading.value = false;
      EventBus.emit("showError", err.message);
    });
}
</script>
