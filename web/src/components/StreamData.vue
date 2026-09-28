<!-- eslint-disable vue/no-v-html -->
<template>
  <div v-if="viewmode === 'cards'">
    <template v-for="(chunk, index) in data" :key="index">
      <v-row
        static
        :class="[title_classes, 'text-caption', 'align-center']"
        no-gutters
      >
        <v-col class="v-col-1 ml-4">
          <v-icon v-if="chunk.Direction === 0" color="red"
            >mdi-arrow-right-thin-circle-outline</v-icon
          >
          <v-icon v-else color="green"
            >mdi-arrow-left-thin-circle-outline</v-icon
          >
          <span>
            {{ chunk.Direction === 0 ? "Client" : "Server" }}
          </span>
        </v-col>
        <v-col v-if="chunk.Time !== undefined" class="v-col-1">
          <v-tooltip location="bottom">
            <template #activator="{ props: tprops }">
              <v-chip v-bind="tprops" size="small" variant="text"
                >+{{
                  formatDateDifference(chunk.Time, data[index - 1]?.Time)
                }}</v-chip
              >
            </template>
            <span>{{ formatDate(chunk.Time) }}</span>
          </v-tooltip>
        </v-col>
        <v-col class="v-col-1">
          {{ formatChunkSize(chunk) }}
        </v-col>
        <v-col v-if="flagIdMatches[index]?.length" class="v-col-2">
          <v-chip
            size="x-small"
            color="amber-darken-2"
            :title="flagIdMatches[index].join(', ')"
            >Flag ID</v-chip
          >
        </v-col>
        <v-col>
          <v-btn-toggle
            v-model="chunk.Presentation"
            mandatory
            density="compact"
            variant="text"
            color="primary"
            class="smol-group"
            @click.stop
          >
            <v-tooltip location="bottom">
              <template #activator="{ props: pprops }">
                <v-btn value="ascii" v-bind="pprops" size="x-small">
                  <v-icon>mdi-text-long</v-icon>
                </v-btn>
              </template>
              <span>ASCII</span>
            </v-tooltip>
            <v-tooltip location="bottom">
              <template #activator="{ props: pprops }">
                <v-btn value="utf-8" v-bind="pprops" size="x-small">
                  <v-icon>mdi-format-font</v-icon>
                </v-btn>
              </template>
              <span>UTF-8</span>
            </v-tooltip>
            <v-tooltip location="bottom">
              <template #activator="{ props: pprops }">
                <v-btn value="hexdump" v-bind="pprops" size="x-small">
                  <v-icon>mdi-format-columns</v-icon>
                </v-btn>
              </template>
              <span>HEXDUMP</span>
            </v-tooltip>
            <v-tooltip location="bottom">
              <template #activator="{ props: pprops }">
                <v-btn value="raw" v-bind="pprops" size="x-small">
                  <v-icon>mdi-hexadecimal</v-icon>
                </v-btn>
              </template>
              <span>RAW</span>
            </v-tooltip>
            <v-tooltip
              v-if="supportsIframeVisualization(chunk)"
              location="bottom"
            >
              <template #activator="{ props: pprops }">
                <v-btn value="web" v-bind="pprops" size="x-small">
                  <v-icon>mdi-web</v-icon>
                </v-btn>
              </template>
              <span>WEB</span>
            </v-tooltip>
          </v-btn-toggle>
        </v-col>
        <v-col class="v-col-2">
          <v-tooltip location="bottom">
            <template #activator="{ props: pprops }">
              <v-btn
                v-bind="pprops"
                size="x-small"
                variant="text"
                icon="mdi-chef-hat"
                @click="openInCyberChef(chunk)"
                @click.stop
              >
              </v-btn>
            </template>
            <span>Open in CyberChef</span>
          </v-tooltip>
          <v-tooltip location="bottom">
            <template #activator="{ props: pprops }">
              <v-btn
                v-bind="pprops"
                size="x-small"
                variant="text"
                @click="downloadChunk(index, chunk)"
                @click.stop
              >
                <v-icon>mdi-download</v-icon>
              </v-btn>
            </template>
            <span>Download</span>
          </v-tooltip>
          <v-tooltip location="bottom">
            <template #activator="{ props: pprops }">
              <v-btn
                v-bind="pprops"
                size="x-small"
                variant="text"
                icon="mdi-content-copy"
                @click="copyToClipboard(chunk)"
                @click.stop
              >
              </v-btn>
            </template>
            <span>Copy Content</span>
          </v-tooltip>
        </v-col>
      </v-row>
      <v-row no-gutters class="break-all ma-4 mt-2">
        <v-col cols="12">
          <span
            v-if="chunk.Presentation === 'ascii'"
            class="chunk"
            :data-chunk-idx="index"
            :class="[classes(chunk)]"
            v-html="inlineAscii(chunk, index)"
          >
          </span>
          <span
            v-else-if="chunk.Presentation === 'utf-8'"
            class="chunk"
            :data-chunk-idx="index"
            :class="[classes(chunk)]"
            v-html="inlineUnicode(chunk, index)"
          >
          </span>
          <pre
            v-else-if="chunk.Presentation === 'hexdump'"
            :class="[classes(chunk), 'hexdump']"
            >{{ hexdump(chunk.Content) }}</pre>

          <span
            v-else-if="chunk.Presentation === 'raw'"
            :class="[classes(chunk)]"
            >{{ inlineHex(chunk.Content) }}<br
          /></span>
          <template v-else-if="chunk.Presentation === 'web'">
            <div
              v-if="supportsIframeVisualization(chunk)"
              class="iframe-content"
            >
              <iframe
                :src="`data:${chunk.ContentType};base64,${chunk.Content}`"
                width="100%"
                height="100%"
                sandbox=""
                csp="default-src 'none'"
              ></iframe>
            </div>
            <span v-else>
              <span class="text-caption">Unsupported content type: </span>
              <span class="text-body-2">{{ chunk.ContentType }}</span>
            </span>
          </template>
        </v-col>
      </v-row>
    </template>
  </div>
  <div v-else>
    <v-card>
      <v-card-text>
        <template v-if="presentation === 'ascii'">
          <span
            v-for="(chunk, index) in data"
            :key="index"
            class="chunk"
            :data-chunk-idx="index"
            :class="[classes(chunk)]"
            v-html="inlineAscii(chunk, index)"
          >
          </span>
        </template>
        <template v-else-if="presentation === 'utf-8'">
          <span
            v-for="(chunk, index) in data"
            :key="index"
            class="chunk"
            :data-chunk-idx="index"
            :class="[classes(chunk)]"
            v-html="inlineUnicode(chunk, index)"
          >
          </span>
        </template>
        <template v-else-if="presentation === 'hexdump'">
          <pre
            v-for="(chunk, index) in data"
            :key="index"
            :class="[classes(chunk), 'hexdump']"
            >{{ hexdump(chunk.Content) }}</pre>
        </template>
        <template v-else>
          <span
            v-for="(chunk, index) in data"
            :key="index"
            :class="[classes(chunk)]"
            >{{ inlineHex(chunk.Content) }}<br
          /></span>
        </template>
      </v-card-text>
    </v-card>
  </div>
</template>

<script lang="ts" setup>
import { Data, DataRegexes } from "@/apiClient";
import { PropType, computed, ref, watch } from "vue";
import { formatDate } from "@/filters";
import {
  escapeRegex,
  handleUnicodeDecode,
  tryURLDecodeIfEnabled,
} from "@/lib/utils";
import moment from "moment";
import prettyBytes from "pretty-bytes";
import { getColorScheme, onColorSchemeChange } from "@/lib/darkmode";
import { useStreamStore } from "@/stores/stream";
import { EventBus } from "./EventBus";
import { CYBERCHEF_URL } from "@/lib/constants";

const stream = useStreamStore();
const props = defineProps({
  viewmode: {
    type: String,
    required: true,
  },
  presentation: {
    type: String,
    required: true,
  },
  data: {
    type: Array as PropType<Data[]>,
    required: true,
  },
  highlightMatches: {
    type: Object as PropType<DataRegexes>,
    required: false,
    default: () => ({ Client: null, Server: null }),
  },
  flagIdMatches: {
    type: Array as PropType<string[][]>,
    required: false,
    default: () => [],
  },
  urlDecode: {
    type: Boolean,
    required: false,
    default: false,
  },
});

const formatDateDifference = (first: string, second: string | undefined) => {
  if (second === undefined) return "0 ms";
  if (first === second) return "0 ms";
  const ms = moment(first).diff(moment(second));
  if (ms < 1000) return `${ms} ms`;
  const seconds = ms / 1000;
  if (seconds < 60) {
    return `${seconds} s`;
  }
  const minutes = Math.floor(seconds / 60);
  return `${minutes}:${seconds} s`;
};

const formatChunkSize = (chunk: Data) => {
  const size = atob(chunk.Content).length;
  return prettyBytes(size, {
    maximumFractionDigits: 1,
    binary: true,
  });
};

type VisualChunk = Data & {
  Presentation: string;
};

const data = ref(
  props.data.map((chunk) => {
    const visualChunk: VisualChunk = {
      ...chunk,
      Presentation: props.presentation,
    };
    return visualChunk;
  }),
);

watch(
  () => props.data,
  (chunks) => {
    data.value = chunks.map((chunk) => ({
      ...chunk,
      Presentation: props.presentation,
    }));
  },
);

const getBgThemeColor = () => {
  const colorScheme = getColorScheme();
  return {
    "bg-grey-lighten-3": colorScheme === "light",
    "bg-grey-darken-3": colorScheme === "dark",
  };
};
const title_classes = ref(getBgThemeColor());
onColorSchemeChange(() => {
  title_classes.value = getBgThemeColor();
});

watch(
  () => props.presentation,
  (newPresentation) => {
    for (const chunk of data.value) {
      chunk.Presentation = newPresentation;
    }
  },
  { immediate: true },
);

const highlightRegex = (highlight: string[] | null) =>
  highlight?.map((regex) => {
    try {
      if (regex === "") return undefined;
      // replace \x{XX} with the actual character
      regex = regex.replace(/\\x{([0-9a-fA-F]{2})}/g, (_, hex) => {
        const decoded = String.fromCharCode(parseInt(hex as string, 16));
        if (escapeRegex.test(decoded)) return `\\${decoded}`;
        return decoded;
      });
      return new RegExp(regex, "g");
    } catch {
      console.error(`Invalid regex: ${regex}`);
    }
  });

const highlightMatchesClient = computed(() =>
  highlightRegex(props.highlightMatches.Client),
);
const highlightMatchesServer = computed(() =>
  highlightRegex(props.highlightMatches.Server),
);

const asciiMap = Array.from({ length: 0x100 }, (_, i) => {
  if (i != 0x0d && i != 0x0a && (i < 0x20 || i > 0x7e)) return ".";
  return `&#x${i.toString(16).padStart(2, "0")};`;
});

const handleHighlightMatches = (
  direction: number,
  chunkData: string,
  asciiEscaped: string[],
  flagIDs: string[],
) => {
  const highlightMatchesRegex =
    direction === 0
      ? highlightMatchesClient.value
      : highlightMatchesServer.value;
  const marks = new Uint8Array(chunkData.length);
  if (highlightMatchesRegex !== undefined) {
    for (const regex of highlightMatchesRegex) {
      if (regex === undefined) continue;
      for (const match of chunkData.matchAll(regex)) {
        for (let i = match.index; i < match.index + match[0].length; i++) {
          marks[i] = 1;
        }
      }
    }
  }
  for (const id of flagIDs) {
    if (id === "") continue;
    let from = 0;
    while (from < chunkData.length) {
      const at = chunkData.indexOf(id, from);
      if (at < 0) break;
      for (let i = at; i < at + id.length; i++) marks[i] = 2;
      from = at + id.length;
    }
  }
  const output: string[] = [];
  let previous = -1;
  for (let i = 0; i < asciiEscaped.length; i++) {
    const current = marks[i];
    if (current !== previous) {
      if (previous !== -1) output.push("</span>");
      const klass =
        current === 2
          ? ' class="flag-id"'
          : current === 1
            ? ' class="mark"'
            : "";
      output.push(`<span${klass} data-offset="${i}">`);
      previous = current;
    }
    output.push(asciiEscaped[i]);
  }
  if (previous !== -1) output.push("</span>");
  return output.join("");
};

const inlineUnicode = (chunk: Data, index: number) => {
  const chunkData = handleUnicodeDecode(chunk, props.urlDecode);
  const asciiEscaped = chunkData.split("").map((c) => {
    const charCode = c.charCodeAt(0);
    return asciiMap[charCode] !== undefined ? asciiMap[charCode] : c;
  });
  return handleHighlightMatches(
    chunk.Direction,
    chunkData,
    asciiEscaped,
    props.flagIdMatches[index] ?? [],
  );
};

const inlineAscii = (chunk: Data, index: number) => {
  const chunkData = tryURLDecodeIfEnabled(atob(chunk.Content), props.urlDecode);
  const asciiEscaped = chunkData
    .split("")
    .map((c) => asciiMap[c.charCodeAt(0)] ?? c);
  return handleHighlightMatches(
    chunk.Direction,
    chunkData,
    asciiEscaped,
    props.flagIdMatches[index] ?? [],
  );
};

const classes = (chunk: Data) => ({
  chunk: true,
  client: chunk.Direction === 0,
  server: chunk.Direction === 1,
});

const inlineHex = (b64: string) => {
  const ui8 = Uint8Array.from(
    atob(b64)
      .split("")
      .map((char) => char.charCodeAt(0)),
  );
  const str = ([] as number[]).slice
    .call(ui8)
    .map((i) => i.toString(16).padStart(2, "0"))
    .join("");
  return str;
};

const hexdump = (b64: string) => {
  const ui8 = Uint8Array.from(
    atob(b64)
      .split("")
      .map((char) => char.charCodeAt(0)),
  );
  const str = ([] as number[]).slice
    .call(ui8)
    .map((i) => i.toString(16).padStart(2, "0"))
    .join("")
    .match(/.{1,2}/g)
    ?.join(" ")
    .match(/.{1,48}/g)
    ?.map(function (str) {
      while (str.length < 48) {
        str += " ";
      }
      let ascii =
        str
          .replace(/ /g, "")
          .match(/.{1,2}/g)
          ?.map(function (ch) {
            let c = String.fromCharCode(parseInt(ch, 16));
            if (!/[ -~]/.test(c)) {
              c = ".";
            }
            return c;
          })
          .join("") ?? "";
      while (ascii.length < 16) {
        ascii += " ";
      }
      return str + " |" + ascii + "|";
    })
    .join("\n");
  return str;
};

const validateMediaTypeWithCharsetParameter = (
  chunk: Data,
  mediaType: string,
) => {
  if (!chunk.ContentType?.toLowerCase().startsWith(mediaType)) return false;
  const params = chunk.ContentType.split(";");
  if (params.length > 2) return false;
  for (let i = 1; i < params.length; i++) {
    const param = params[i].trim().toLowerCase();
    if (!param.startsWith("charset=")) return false;
    const charset = param.substring("charset=".length);
    if (!/^[a-zA-Z0-9\-+./]+$/.test(charset)) return false;
  }
  return true;
};

const isHTMLMediaType = (chunk: Data) => {
  // text/html;charset=UTF-8
  return validateMediaTypeWithCharsetParameter(chunk, "text/html");
};

const isImageMediaType = (chunk: Data) => {
  // https://developer.mozilla.org/en-US/docs/Web/HTTP/Guides/MIME_types#image_types
  // https://www.iana.org/assignments/media-types/media-types.xhtml#image
  return [
    "image/apng",
    "image/avif",
    "image/gif",
    "image/jpeg",
    "image/png",
    "image/svg+xml",
    "image/webp",
    "image/x-icon",
    "image/bmp",
  ].includes(chunk.ContentType?.toLowerCase() ?? "");
};

const supportsIframeVisualization = (chunk: Data) => {
  return isHTMLMediaType(chunk) || isImageMediaType(chunk);
};
const downloadChunk = (index: number, chunk: Data) => {
  const blob = new Blob([atob(chunk.Content)], {
    type: "application/octet-stream",
  });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = `chunk-${stream.id}-${index}.bin`;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);
};

const copyToClipboard = (chunk: VisualChunk) => {
  let content;
  switch (chunk.Presentation) {
    case "ascii":
      content = tryURLDecodeIfEnabled(atob(chunk.Content), props.urlDecode);
      break;
    case "utf-8":
      content = handleUnicodeDecode(chunk, props.urlDecode);
      break;
    case "hexdump":
      content = hexdump(chunk.Content) ?? "";
      break;
    case "raw":
      content = inlineHex(chunk.Content);
      break;
    default:
      EventBus.emit(
        "showError",
        `Unknown presentation format: ${chunk.Presentation}`,
      );
      return;
  }
  navigator.clipboard
    .writeText(content)
    .then(() => {
      EventBus.emit("showMessage", "Copied content to clipboard.");
    })
    .catch((err) => {
      EventBus.emit("showError", `Failed to copy to clipboard: ${err}`);
    });
};

function openInCyberChef(chunk: Data) {
  window.open(
    `${CYBERCHEF_URL}#input=${encodeURIComponent(chunk.Content)}`,
    "_blank",
    "noopener,noreferrer",
  );
}
</script>
<style scoped>
.chunk {
  white-space: break-spaces;
  font-family: monospace, monospace;
}
.server {
  color: #000080;
  background-color: #eeedfc;

  &.hexdump {
    margin-left: 2em;
  }
}
.server :deep(.mark) {
  background-color: #9090ff;
}
.chunk :deep(.flag-id) {
  background-color: #ffd54f;
  color: #212121;
  border-radius: 2px;
}
.client {
  color: #800000;
  background-color: #faeeed;
}
.client :deep(.mark) {
  background-color: #ff8e5e;
}

.v-theme--dark {
  .server {
    color: #ffffff;
    background-color: #261858;
  }

  .client {
    color: #ffffff;
    background-color: #561919;
  }
}

.break-all {
  word-break: break-all;
  overflow-wrap: break-word;
}

.smol-group {
  height: 24px !important;
}

.iframe-content {
  max-height: 300px;
  resize: both;
  overflow: hidden;
}
.iframe-content iframe {
  max-height: 300px;
}
</style>
