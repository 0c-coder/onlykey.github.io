var pagesList = {
  "connect": { icon: "fa-plug", title: "Connect Agent", sort: 5 }
};

module.exports = {
  pagesList: pagesList,
  consumes: ["app"],
  provides: ["plugin_onlyagent_connect"],

  setup: function(options, imports, register) {
    var page = {
      view: require("./onlyagent_connect.page.html").default,

      init: function(app, $page) {
        page.setup(app, $page);
      },

      setup: function(app, $page) {
        var $ = app.$;
        var API_BASE = "https://api.onlyagent.app";
        var MCP_URL = "https://mcp.onlyagent.app/mcp";
        var state = {
          hid: null,
          screen: null,
          ws: null,
          deviceId: sessionStorage.getItem("onlyagent_device_id") || null,
          ownerToken: sessionStorage.getItem("onlyagent_owner_token") || "",
          stopped: false
        };

        var ownerInput = $page.find("#oa-owner-token");
        ownerInput.val(state.ownerToken);

        setStatus("#oa-secure-status", window.isSecureContext, "Secure context", "A secure context is required");
        setStatus("#oa-webhid-status", !!navigator.hid, "WebHID available", "WebHID is unavailable in this browser");
        setStatus("#oa-capture-status", !!(navigator.mediaDevices && navigator.mediaDevices.getDisplayMedia),
          "Browser screen capture available", "Browser screen capture unavailable — hardware capture can be used");

        $page.find("#oa-connect-device").on("click", connectHid);
        $page.find("#oa-share-screen").on("click", shareScreen);
        $page.find("#oa-stop-screen").on("click", stopScreen);
        $page.find("#oa-cloud-login").on("click", connectCloud);
        $page.find("#oa-create-agent").on("click", createAgentGrant);
        $page.find("#oa-emergency-stop").on("click", emergencyStop);

        async function connectHid() {
          if (!navigator.hid) return alert("WebHID is not available in this browser.");
          try {
            var devices = await navigator.hid.requestDevice({ filters: [{ usagePage: 0xFF00 }] });
            if (!devices.length) return;
            state.hid = devices[0];
            if (!state.hid.opened) await state.hid.open();
            state.hid.addEventListener("inputreport", onHidReport);
            $page.find("#oa-device-status").removeClass("text-muted text-danger").addClass("text-success")
              .text("Connected: " + (state.hid.productName || "OnlyAgent"));
            sendDeviceStatus();
          } catch (e) {
            $page.find("#oa-device-status").removeClass("text-success").addClass("text-danger").text(e.message);
          }
        }

        async function shareScreen() {
          try {
            state.screen = await navigator.mediaDevices.getDisplayMedia({ video: true, audio: false });
            var video = $page.find("#oa-capture-video")[0];
            video.srcObject = state.screen;
            state.screen.getVideoTracks()[0].addEventListener("ended", function() {
              state.screen = null;
              $page.find("#oa-screen-status").text("Not sharing");
              sendDeviceStatus();
            });
            state.stopped = false;
            $page.find("#oa-screen-status").removeClass("text-muted text-danger").addClass("text-success")
              .text("Browser screen capture active");
            sendDeviceStatus();
          } catch (e) {
            $page.find("#oa-screen-status").addClass("text-danger").text(e.message);
          }
        }

        function stopScreen() {
          if (state.screen) state.screen.getTracks().forEach(function(t) { t.stop(); });
          state.screen = null;
          $page.find("#oa-screen-status").removeClass("text-success").addClass("text-muted").text("Not sharing");
          sendDeviceStatus();
        }

        async function connectCloud() {
          try {
            state.ownerToken = ownerInput.val().trim();
            if (state.ownerToken) sessionStorage.setItem("onlyagent_owner_token", state.ownerToken);

            if (!state.deviceId) {
              var created = await api("/api/devices", {
                method: "POST",
                body: JSON.stringify({ name: "OnlyAgent Browser Device" })
              });
              state.deviceId = created.device.id;
              sessionStorage.setItem("onlyagent_device_id", state.deviceId);
            }

            var wsToken = await api("/api/devices/" + encodeURIComponent(state.deviceId) + "/ws-token", {
              method: "POST",
              body: "{}"
            });

            if (state.ws) state.ws.close();
            var wsUrl = API_BASE.replace(/^http/, "ws") + "/device/ws/" + encodeURIComponent(state.deviceId) +
              "?token=" + encodeURIComponent(wsToken.token);

            state.ws = new WebSocket(wsUrl);
            state.ws.binaryType = "arraybuffer";
            state.ws.onopen = function() {
              $page.find("#oa-cloud-status").removeClass("text-muted text-danger").addClass("text-success")
                .text("Connected — " + state.deviceId);
              sendDeviceStatus();
            };
            state.ws.onclose = function() {
              $page.find("#oa-cloud-status").removeClass("text-success").addClass("text-muted").text("Disconnected");
            };
            state.ws.onmessage = onCloudMessage;
          } catch (e) {
            $page.find("#oa-cloud-status").removeClass("text-success").addClass("text-danger").text(e.message);
          }
        }

        async function createAgentGrant() {
          if (!state.deviceId) return alert("Connect OnlyAgent Cloud first.");
          try {
            var scopes = [];
            $page.find(".oa-scope:checked").each(function() { scopes.push($(this).val()); });
            var data = await api("/api/devices/" + encodeURIComponent(state.deviceId) + "/grants", {
              method: "POST",
              body: JSON.stringify({
                name: $page.find("#oa-agent-name").val() || "Remote Agent",
                scopes: scopes,
                ttl_days: 7
              })
            });

            var token = data.grant.token;
            var hermes = "mcp_servers:\n  onlyagent:\n    url: \"" + MCP_URL + "\"\n    headers:\n      Authorization: \"Bearer " + token + "\"";
            var openclaw = JSON.stringify({
              mcp: { servers: { onlyagent: {
                url: MCP_URL,
                transport: "streamable-http",
                headers: { Authorization: "Bearer " + token }
              } } }
            }, null, 2);

            $page.find("#oa-agent-output").html(
              "<div class='alert alert-warning'><strong>Copy this credential now.</strong> Only its hash is stored by OnlyAgent Cloud.</div>" +
              "<h4>Agent token</h4><pre class='oa-token'></pre>" +
              "<h4>Hermes</h4><pre class='oa-hermes'></pre>" +
              "<h4>OpenClaw</h4><pre class='oa-openclaw'></pre>"
            );
            $page.find(".oa-token").text(token);
            $page.find(".oa-hermes").text(hermes);
            $page.find(".oa-openclaw").text(openclaw);
          } catch (e) {
            alert(e.message);
          }
        }

        async function onCloudMessage(event) {
          if (typeof event.data !== "string") return;
          var msg;
          try { msg = JSON.parse(event.data); } catch (e) { return; }
          if (msg.type !== "command") return;

          var id = msg.id;
          var command = msg.command;
          var params = msg.params || {};

          try {
            if (command === "screenshot") {
              await sendScreenshot(id, params);
              return;
            }
            if (command === "get_state") {
              sendResult(id, true, {
                browser_connected: true,
                hardware_connected: !!state.hid,
                screen_shared: !!state.screen,
                capture_source: state.screen ? "browser" : (state.hid ? "hardware" : "none"),
                control_enabled: !state.stopped
              });
              return;
            }
            if (command === "stop") {
              await emergencyStop();
              sendResult(id, true, { stopped: true });
              return;
            }
            if (state.stopped) throw new Error("Remote control is stopped");
            if (!state.hid) throw new Error("OnlyAgent hardware is not connected");
            await sendHardwareCommand(command, params);
            sendResult(id, true, { ok: true });
          } catch (e) {
            sendResult(id, false, null, e.message);
          }
        }

        async function sendScreenshot(id, params) {
          if (state.screen) return sendBrowserScreenshot(id, params);
          if (state.hid) {
            requestHardwareCapture(id, params);
            return;
          }
          throw new Error("No capture source available");
        }

        async function sendBrowserScreenshot(id, params) {
          var video = $page.find("#oa-capture-video")[0];
          var canvas = $page.find("#oa-capture-canvas")[0];
          var ctx = canvas.getContext("2d");
          var settings = state.screen.getVideoTracks()[0].getSettings();
          var sourceW = settings.width || video.videoWidth || 1280;
          var sourceH = settings.height || video.videoHeight || 720;
          var maxW = Math.max(320, Math.min(Number(params.max_width || 1280), 3840));
          var width = Math.min(sourceW, maxW);
          var height = Math.max(1, Math.round(sourceH * width / sourceW));
          canvas.width = width;
          canvas.height = height;
          ctx.drawImage(video, 0, 0, width, height);
          var quality = Math.max(.2, Math.min(Number(params.quality || 75) / 100, .95));
          var blob = await new Promise(function(resolve) { canvas.toBlob(resolve, "image/jpeg", quality); });
          var jpeg = new Uint8Array(await blob.arrayBuffer());
          sendBinaryScreenshot(id, jpeg, width, height, "image/jpeg");
        }

        function sendBinaryScreenshot(id, jpeg, width, height, mime) {
          if (!state.ws || state.ws.readyState !== WebSocket.OPEN) throw new Error("Cloud relay is offline");
          var header = new TextEncoder().encode(JSON.stringify({
            type: "screenshot", id: id, mime: mime || "image/jpeg", width: width, height: height
          }));
          var packet = new Uint8Array(4 + header.length + jpeg.length);
          new DataView(packet.buffer).setUint32(0, header.length, true);
          packet.set(header, 4);
          packet.set(jpeg, 4 + header.length);
          state.ws.send(packet);
        }

        function requestHardwareCapture(requestId, params) {
          sendVendorJson({
            type: "capture_frame",
            request_id: requestId,
            max_width: Number(params.max_width || 1280),
            quality: Number(params.quality || 75)
          });
        }

        async function sendHardwareCommand(command, params) {
          return sendVendorJson({ type: "computer_command", command: command, params: params || {} });
        }

        async function emergencyStop() {
          state.stopped = true;
          if (state.hid) {
            try { await sendVendorJson({ type: "emergency_stop" }); } catch (e) {}
          }
          sendDeviceStatus();
        }

        function sendVendorJson(obj) {
          if (!state.hid || !state.hid.opened) throw new Error("OnlyAgent hardware is not connected");
          var encoded = new TextEncoder().encode(JSON.stringify(obj));
          if (encoded.length > 900) throw new Error("Control message is too large");
          var report = new Uint8Array(1024);
          report.set(encoded, 0);
          return state.hid.sendReport(0, report);
        }

        function onHidReport(event) {
          // T113-S4 follow-up: parse OA v0.1 FRAME_START / FRAME_DATA / FRAME_END here.
        }

        function sendResult(id, ok, result, error) {
          if (!state.ws || state.ws.readyState !== WebSocket.OPEN) return;
          state.ws.send(JSON.stringify({ type: "result", id: id, ok: ok, result: result, error: error }));
        }

        function sendDeviceStatus() {
          if (!state.ws || state.ws.readyState !== WebSocket.OPEN) return;
          state.ws.send(JSON.stringify({
            type: "status",
            state: {
              device_id: state.deviceId,
              browser_connected: true,
              hardware_connected: !!state.hid,
              screen_shared: !!state.screen,
              capture_source: state.screen ? "browser" : (state.hid ? "hardware" : "none"),
              control_enabled: !state.stopped
            }
          }));
        }

        async function api(path, options) {
          options = options || {};
          options.headers = options.headers || {};
          options.headers["content-type"] = "application/json";
          if (state.ownerToken) options.headers["authorization"] = "Bearer " + state.ownerToken;
          var response = await fetch(API_BASE + path, options);
          if (!response.ok) throw new Error(response.status + ": " + await response.text());
          if (response.status === 204) return null;
          return response.json();
        }

        function setStatus(selector, good, yes, no) {
          $page.find(selector)
            .toggleClass("text-success", !!good)
            .toggleClass("text-danger", !good)
            .text(good ? yes : no);
        }
      }
    };

    pagesList.connect = page;
    register(null, { plugin_onlyagent_connect: { pagesList: pagesList } });
  }
};
