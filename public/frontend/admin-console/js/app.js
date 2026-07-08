(function (app) {
    'use strict';

    const actions = {
        'refresh-all': () => refreshAll(),
        'open-admin-account': () => openAdminAccount(),
        'reload-admin-profile': () => loadAdminProfile({notify: true}),
        'clear-remember-login': () => clearRememberLogin(),
        'logout-admin': () => logoutAdmin(),
        'reset-admin-profile-form': () => resetAdminProfileForm(),
        'load-apps': () => loadApps(),
        'load-variables': () => loadVariablesPage(),
        'load-remote-api': () => loadRemoteApiPage(),
        'load-remote-api-logs': () => loadRemoteApiLogsPage(),
        'clear-remote-api-logs': () => clearRemoteApiLogs(),
        'load-cloud-storage': () => loadCloudStoragePage(),
        'open-cloud-config': () => openCloudConfigModal(),
        'open-cloud-upload-modal': () => openCloudUploadModal(),
        'open-cloud-token-modal': () => openCloudTokenModal(),
        'copy-cloud-file-link': (node) => copyCloudFileLink(node),
        'cloud-file-detail': (node) => showCloudFileDetail(node),
        'cloud-file-delete': (node) => deleteCloudFile(node),
        'refresh-cloud-download-token': () => refreshCloudDownloadToken(),
        'set-cloud-token-status': (node) => setCloudDownloadTokenStatus(node),
        'copy-cloud-download-token': () => copyCloudDownloadToken(),
        'test-cloud-config': () => testCloudConfig(),
        'remote-api-log-detail': (node) => showRemoteApiLogDetail(node),
        'open-remote-api-token-modal': () => openRemoteApiTokenModal(),
        'remote-api-token-status': (node) => setRemoteApiTokenStatus(node),
        'remote-api-token-secret': (node) => showRemoteApiTokenSecret(node),
        'remote-api-token-delete': (node) => deleteRemoteApiToken(node),
        'remote-api-log-delete': (node) => deleteRemoteApiLog(node),
        'open-app-modal': () => openAppModal(),
        'open-card-modal': () => openCardModal(),
        'open-card-import-modal': () => openCardImportModal(),
        'close-modal': (node) => closeModal(node.dataset.modal),
        'cleanup-nonces': () => cleanupNonces(),
        'copy-secret': () => copySecret(),
        'copy-value': (node) => copyValue(node),
        'copy-cards': () => copyGeneratedCards(),
        'export-cards': () => exportGeneratedCards(),
        'export-current-cards': () => exportCurrentCards(),
        'toggle-app-selection': (node) => toggleSelection('app', node.checked),
        'toggle-card-selection': (node) => toggleSelection('card', node.checked),
        'toggle-message-selection': (node) => toggleSelection('message', node.checked),
        'toggle-variable-selection': (node) => toggleSelection('variable', node.checked),
        'select-expired-cards': () => selectCardsByPreset('expired'),
        'select-active-cards': () => selectCardsByPreset('active'),
        'select-inactive-cards': () => selectCardsByPreset('0'),
        'open-app-config-view': (node) => openAppConfigView(node.dataset.appConfigView),
        'open-app-batch-actions': () => openAppBatchActions(),
        'batch-enable-apps': () => batchEnableApps(),
        'batch-disable-apps': () => batchDisableApps(),
        'batch-delete-apps': () => batchDeleteApps(),
        'open-card-actions': (node) => openCardActions(node),
        'switch-auth-app': (node) => switchAuthorizationApp(node.dataset.app),
        'close-auth-app': (node) => closeAuthorizationApp(node.dataset.app),
        'back-apps': () => activateMainView('apps'),
        'refresh-auth': () => refreshAuthData(),
        'open-card-devices': (node) => openCardDevices(node),
        'selected-card-actions': () => openSelectedCardActions(),
        'reload-selected-card-devices': () => reloadSelectedCardDevices(true),
        'open-card-batch-actions': () => openCardBatchActions(),
        'batch-enable-cards': () => batchEnableCards(),
        'open-sdk-downloads': () => openSdkDownloads(),
        'download-selected-sdk': () => downloadSelectedSdk(),
        'open-integration-section': () => openIntegrationSection(),
        'load-app-integration': () => loadIntegrationPanel(),
        'copy-integration-params': () => copyIntegrationParams(),
        'generate-current-app-keypair': () => generateCurrentAppKeyPair(),
        'delete-current-app': () => deleteCurrentApp(),
        'app-status': (node) => setAppStatus(node),
        'load-cards': () => loadCards(),
        'card-prev-page': () => changeCardPage(-1),
        'card-next-page': () => changeCardPage(1),
        'load-messages': () => loadMessages(),
        'batch-disable-cards': () => batchDisableCards(),
        'batch-delete-cards': () => batchDeleteCards(),
        'batch-enable-card-devices': () => batchSetCardDevicesStatus(1),
        'batch-disable-card-devices': () => batchSetCardDevicesStatus(0),
        'batch-unbind-card-devices': () => batchUnbindCardDevices(),
        'card-status': (node) => setCardStatus(node),
        'card-delete': (node) => deleteCard(node),
        'card-add-time': (node) => openTimeModal(node, 'add'),
        'card-reduce-time': (node) => openTimeModal(node, 'reduce'),
        'card-reset-time': (node) => openTimeModal(node, 'reset'),
        'card-reset-uses': (node) => resetCardUses(node),
        'card-unbind-device': (node) => unbindCardDevice(node),
        'card-unbind-all': (node) => unbindAllCardDevices(node),
        'device-status': (node) => setDeviceStatus(node),
        'message-detail': (node) => showMessageDetail(node),
        'message-read': (node) => readMessage(node),
        'message-handling': (node) => startHandlingMessage(node),
        'message-handle': (node) => handleMessage(node),
        'message-archive': (node) => archiveMessage(node),
        'message-delete': (node) => deleteMessage(node),
        'message-action': (node) => actMessage(node),
        'clear-app-activity': () => clearAppActivityData(),
        'batch-read-messages': () => batchUpdateMessages('/admin/messages/read', '消息已批量标记已读'),
        'batch-handling-messages': () => batchUpdateMessages('/admin/messages/handling', '消息已批量标记处理中'),
        'batch-handle-messages': () => batchUpdateMessages('/admin/messages/handle', '消息已批量处理'),
        'batch-archive-messages': () => batchUpdateMessages('/admin/messages/archive', '消息已批量归档'),
        'batch-add-time-cards': () => openBatchCardDurationModal('add'),
        'batch-reduce-time-cards': () => openBatchCardDurationModal('reduce'),
        'batch-reset-uses-cards': () => batchResetCardUses(),
        'open-card-range-operation': () => openCardRangeOperationModal(),
        'open-variable-modal': (node) => openVariableModal(node),
        'edit-variable': (node) => editVariable(node),
        'open-variable-actions': (node) => openVariableActions(node),
        'open-variable-batch-actions': () => openVariableBatchActions(),
        'batch-enable-variables': () => batchEnableVariables(),
        'batch-disable-variables': () => batchDisableVariables(),
        'batch-delete-variables': () => batchDeleteVariables(),
        'variable-status': (node) => toggleVariableStatus(node),
        'variable-delete': (node) => deleteVariable(node),
        'variable-convert': (node) => convertVariable(node),
        'variable-app-toggle': (node) => toggleVariableAppSelection(node.dataset.id),
        'variable-app-remove': (node) => removeVariableAppSelection(node.dataset.id),
        'reload-site-settings': () => loadSiteSettings(),
        'confirm-yes': () => resolveConfirm(true),
        'confirm-no': () => resolveConfirm(false)
    };

    const formHandlers = {
        'admin-profile-form': onSaveAdminProfile,
        'app-form': onCreateApp,
        'card-form': onCreateCards,
        'card-import-form': onImportCards,
        'app-settings-form': onSaveAppSettings,
        'app-api-form': onSaveAppApi,
        'config-form': onSaveConfig,
        'variable-form': onSaveVariable,
        'remote-api-token-form': onCreateRemoteApiToken,
        'cloud-upload-form': onUploadCloudFile,
        'cloud-storage-config-form': onSaveCloudConfig,
        'time-form': onAdjustCardTime,
        'card-range-form': onCardRangeOperation,
        'site-settings-form': onSaveSiteSettings
    };

    const sdkTypeLabels = {
        android: 'Android',
        windows: 'Windows',
        macos: 'macOS',
        linux: 'Linux',
        cpp: 'Windows',
        python: 'Python'
    };

    const customCardImportConfig = {
        maxCards: 500,
        maxLength: 70000,
        tokenPattern: /[\s,;，；、|]+/u,
        cardPattern: /^[A-Za-z0-9_-]{8,128}$/
    };
    const maxCardDurationSeconds = 315360000;
    const durationUnits = {
        hour: {seconds: 3600, max: 87600},
        day: {seconds: 86400, max: 3650},
        month: {seconds: 2592000, max: 121}
    };

    let confirmResolver = null;
    let selectedCardSyncSerial = 0;
    let cardSearchTimer = 0;
    let variableSearchTimer = 0;
    let remoteApiLogSearchTimer = 0;
    let cloudFileSearchTimer = 0;
    let selectedVariableAppIdSet = new Set();
    const mainViews = new Set(['dashboard', 'apps', 'variables', 'remoteApi', 'cloudStorage', 'settings', 'account', 'authorization']);
    const hashViews = new Set(['dashboard', 'apps', 'variables', 'remoteApi', 'cloudStorage', 'settings', 'account']);

    document.addEventListener('DOMContentLoaded', init);

    function init() {
        bindEvents();
        window.addEventListener('hashchange', onHashChange);
        activateMainView(currentHashView());
        app.view.setAppConfigView(app.state.appConfigView);
        app.view.setRemoteApiView(app.state.remoteApiView);
        app.view.setCloudStorageView(app.state.cloudStorageView);
        renderInitialState();
        runAsync(bootstrap);
    }

    function renderInitialState() {
        app.view.renderOverviewLoading();
        app.view.renderAppsLoading();
        app.view.renderRecentActivityLoading();
        app.view.renderSelectedCardEmpty();
        app.view.renderIntegrationDocs(null);
    }

    function bindEvents() {
        bindFilters();
        app.elements.sideToggle.addEventListener('click', toggleSide);
        app.elements.mobileMask.addEventListener('click', app.view.closeMobileSide);
        document.addEventListener('keydown', onDocumentKeydown);
        document.addEventListener('click', onDocumentClick);
        document.addEventListener('change', onDocumentChange);
        document.addEventListener('input', onDocumentInput);
        document.addEventListener('submit', onDocumentSubmit);
    }

    function onDocumentSubmit(event) {
        const handler = formHandlers[event.target.id];
        if (!handler) {
            return;
        }
        event.preventDefault();
        runAsync(() => handler(event.target), event.submitter);
    }

    function bindFilters() {
        bindCardFilter(app.elements.filters.cardSearch, 'search');
        bindCardFilter(app.elements.filters.cardStatus, 'status', 'change');
        bindCardFilter(app.elements.filters.cardDuration, 'durationCategory', 'change');
        if (app.elements.filters.cardPageSize) {
            app.elements.filters.cardPageSize.addEventListener('change', onCardPageSizeChange);
        }
        bindFilter(app.elements.filters.messageStatus, 'messages', 'status', loadMessages, 'change');
        bindFilter(app.elements.filters.messageRisk, 'messages', 'risk', loadMessages, 'change');
        bindFilter(app.elements.filters.messageAction, 'messages', 'action', loadMessages, 'change');
        bindFilter(app.elements.filters.messageEventType, 'messages', 'eventType', loadMessages, 'change');
        bindFilter(app.elements.filters.messageCardFingerprint, 'messages', 'cardFingerprint', loadMessages);
        bindFilter(app.elements.filters.messageInstallId, 'messages', 'installId', loadMessages);
        bindFilter(app.elements.filters.messageIp, 'messages', 'ip', loadMessages);
        bindVariableFilter(app.elements.filters.variableSearch, 'search');
        bindVariableFilter(app.elements.filters.variableScope, 'scope', 'change');
        bindVariableFilter(app.elements.filters.variableStatus, 'status', 'change');
        bindVariableFilter(app.elements.filters.variableApp, 'appId', 'change');
        bindRemoteApiFilters();
        bindCloudFileFilters();
        app.elements.filters.messageRange.addEventListener('change', onMessageRangeChange);
        app.elements.filters.messageStart.addEventListener('change', onMessageDateChange);
        app.elements.filters.messageEnd.addEventListener('change', onMessageDateChange);
    }

    function bindFilter(element, group, key, renderer, eventName = 'input') {
        if (!element) {
            return;
        }
        element.addEventListener(eventName, () => {
            app.state.filters[group][key] = element.value.trim();
            runAsync(renderer);
        });
    }

    function bindCardFilter(element, key, eventName = 'input') {
        if (!element) {
            return;
        }
        element.addEventListener(eventName, () => {
            app.state.filters.cards[key] = element.value.trim();
            resetCardPage();
            if (eventName === 'input') {
                clearTimeout(cardSearchTimer);
                cardSearchTimer = window.setTimeout(() => runAsync(loadCards), 250);
                return;
            }
            runAsync(loadCards);
        });
    }

    function bindVariableFilter(element, key, eventName = 'input') {
        if (!element) {
            return;
        }
        element.addEventListener(eventName, () => {
            app.state.filters.variables[key] = element.value.trim();
            if (eventName === 'input') {
                clearTimeout(variableSearchTimer);
                variableSearchTimer = window.setTimeout(() => runAsync(loadVariablesPage), 250);
                return;
            }
            runAsync(loadVariablesPage);
        });
    }

    function bindRemoteApiFilters() {
        bindFilter(app.elements.filters.remoteApiTokenSearch, 'remoteApiTokens', 'search', loadRemoteApiTokens);
        bindFilter(app.elements.filters.remoteApiTokenStatus, 'remoteApiTokens', 'status', loadRemoteApiTokens, 'change');
        bindRemoteApiLogFilter(app.elements.filters.remoteApiLogSearch, 'search');
        bindRemoteApiLogFilter(app.elements.filters.remoteApiLogStatus, 'status', 'change');
        bindRemoteApiLogFilter(app.elements.filters.remoteApiLogToken, 'tokenId', 'change');
    }

    function bindRemoteApiLogFilter(element, key, eventName = 'input') {
        if (!element) {
            return;
        }
        element.addEventListener(eventName, () => {
            app.state.filters.remoteApiLogs[key] = element.value.trim();
            if (eventName === 'input') {
                clearTimeout(remoteApiLogSearchTimer);
                remoteApiLogSearchTimer = window.setTimeout(() => runAsync(loadRemoteApiLogs), 250);
                return;
            }
            runAsync(loadRemoteApiLogs);
        });
    }

    function bindCloudFileFilters() {
        bindCloudFileFilter(app.elements.filters.cloudFileSearch, 'search');
        bindCloudFileFilter(app.elements.filters.cloudFileProvider, 'provider', 'change');
        bindCloudFileFilter(app.elements.filters.cloudFileStatus, 'status', 'change');
    }

    function bindCloudFileFilter(element, key, eventName = 'input') {
        if (!element) {
            return;
        }
        element.addEventListener(eventName, () => {
            app.state.filters.cloudFiles[key] = element.value.trim();
            if (eventName === 'input') {
                clearTimeout(cloudFileSearchTimer);
                cloudFileSearchTimer = window.setTimeout(() => runAsync(loadCloudFiles), 250);
                return;
            }
            runAsync(loadCloudFiles);
        });
    }

    function onDocumentClick(event) {
        const authNode = event.target.closest('[data-auth-view]');
        if (authNode) {
            runAsync(() => changeAuthSection(authNode.dataset.authView), authNode);
            return;
        }
        const viewNode = event.target.closest('[data-view]');
        if (viewNode) {
            runAsync(() => changeMainView(viewNode.dataset.view), viewNode);
            return;
        }
        const appConfigViewNode = event.target.closest('[data-app-config-view]');
        if (appConfigViewNode) {
            actions['open-app-config-view'](appConfigViewNode);
            return;
        }
        const remoteApiViewNode = event.target.closest('[data-remote-api-view]');
        if (remoteApiViewNode) {
            runAsync(() => openRemoteApiView(remoteApiViewNode.dataset.remoteApiView), remoteApiViewNode);
            return;
        }
        const actionNode = event.target.closest('[data-action]');
        if (actionNode && actions[actionNode.dataset.action]) {
            runAsync(() => actions[actionNode.dataset.action](actionNode), actionNode);
            return;
        }
        const appCardNode = event.target.closest('[data-open-auth-card]');
        if (appCardNode && !isInteractiveAppCardTarget(event.target)) {
            runAsync(() => enterAuthorizationApp(appCardNode.dataset.app, 'cards'), appCardNode);
        }
    }

    function onDocumentChange(event) {
        const target = event.target;
        if (target.matches('input[data-app-id], input[data-card-id], input[data-message-id], input[data-variable-id]')) {
            const type = target.matches('input[data-app-id]')
                ? 'app'
                : target.matches('input[data-card-id]')
                    ? 'card'
                    : target.matches('input[data-message-id]')
                        ? 'message'
                        : 'variable';
            syncSelectionInput(target, type);
            updateSelectionState(type);
        }
        if (target.matches('#variable-scope')) {
            updateVariableScopeFields();
        }
        if (target.matches('[data-duration-control] [name="duration_unit"]')) {
            syncDurationControl(target.closest('[data-duration-control]'));
        }
        if (target.matches('[data-card-rule-form] [name="card_type"]')) {
            updateCardTypeFields(target.form);
        }
        if (target.matches('#card-range-form [name="operation"]')) {
            syncCardRangeOperationForm(target.form);
        }
        if (target.matches('#cloud-upload-file')) {
            runAsync(() => syncCloudUploadFile(target));
        }
        if (target.matches('#cloud-storage-config-form [name="provider"]')) {
            app.view.renderCloudConfigForm(app.state.cloudStorageConfigs, app.state.cloudStorageSummary?.default_config || {});
        }
    }

    function onDocumentInput(event) {
        if (event.target.matches('#card-import-form [name="custom_cards"]')) {
            syncCustomCardImport(event.target.form);
        }
        if (event.target.matches('#variable-app-search')) {
            renderVariableAppPicker();
        }
    }

    function onDocumentKeydown(event) {
        if (event.key !== 'Escape') {
            const target = event.target;
            if (target instanceof Element && (event.key === 'Enter' || event.key === ' ') && target.matches('[data-open-auth-card]')) {
                event.preventDefault();
                runAsync(() => enterAuthorizationApp(target.dataset.app, 'cards'), target);
            }
            return;
        }
        const confirmOpen = Boolean(document.getElementById('confirm-modal'));
        if (confirmOpen) {
            resolveConfirm(false);
            return;
        }
        closeTopModal();
    }

    async function bootstrap() {
        try {
            await refreshSession();
        } catch (error) {
            if (isLoginRequired(error)) {
                redirectToLogin();
                return;
            }
            app.elements.root.classList.remove('auth-pending');
            throw error;
        }
    }

    function isLoginRequired(error) {
        return error instanceof Error && /请先登录后台管理端|ADMIN_LOGIN_REQUIRED/.test(error.message);
    }

    function redirectToLogin() {
        window.location.replace(app.state.loginUrl);
    }

    async function refreshSession() {
        app.saveSession(await app.http.createSession());
        app.elements.root.classList.remove('auth-pending');
        await Promise.all([
            loadAdminProfile(),
            loadSiteSettings(),
            refreshAll({silent: true})
        ]);
    }

    async function loadAdminProfile(options = {}) {
        const data = await app.http.admin('/admin/profile/get', {});
        app.view.renderAdminProfile(data.profile || null);
        if (options.notify) {
            app.view.showNotice('账号资料已刷新');
        }
        return data.profile || null;
    }

    async function loadSiteSettings() {
        const data = await app.http.admin('/admin/site/get', {});
        const settings = data.settings || {};
        app.view.applySiteBranding(settings);
        app.view.fillSiteSettingsForm(settings);
    }

    async function onSaveSiteSettings(form) {
        const currentSettings = app.state.siteSettings || {};
        const customJson = clonePlainObject(currentSettings.custom_json || {});
        const webConfig = compactObject({
            login_title: form.login_title.value.trim(),
            login_subtitle: form.login_subtitle.value.trim(),
            login_badge: form.login_badge.value.trim(),
            login_notice: form.login_notice.value.trim(),
            side_mascot_text: form.side_mascot_text.value.trim()
        });

        if (Object.keys(webConfig).length > 0) {
            customJson.web = webConfig;
        } else {
            delete customJson.web;
        }

        const payload = {
            hostname: form.hostname.value.trim(),
            site_subtitle: form.site_subtitle.value.trim(),
            siteurl: currentSettings.siteurl || '',
            logo_url: form.logo_url.value.trim(),
            contact: form.contact.value.trim(),
            footer_text: form.footer_text.value.trim(),
            announcement: form.announcement.value.trim(),
            custom_json: customJson
        };

        const data = await app.http.admin('/admin/site/update', payload);
        const settings = data.settings || payload;
        app.view.applySiteBranding(settings);
        app.view.fillSiteSettingsForm(settings);
        app.view.showNotice('站点配置已保存');
    }

    function compactObject(values) {
        return Object.fromEntries(Object.entries(values).filter(([, value]) => value !== ''));
    }

    function clonePlainObject(value) {
        if (!value || typeof value !== 'object' || Array.isArray(value)) {
            return {};
        }
        return JSON.parse(JSON.stringify(value));
    }

    async function refreshAll(options) {
        await Promise.all([
            loadApps(),
            loadOverview()
        ]);
        if (app.state.currentView === 'variables') {
            await loadVariablesPage();
        }
        if (app.state.currentView === 'remoteApi') {
            await loadRemoteApiPage();
        }
        if (app.state.currentView === 'cloudStorage') {
            await loadCloudStoragePage();
        }
        await loadDashboardActivity();
        syncHeaderLabel();
        if (!options?.silent) {
            app.view.showNotice('数据已刷新');
        }
    }

    async function loadOverview() {
        app.view.renderOverviewLoading();
        app.view.renderOverview(await app.http.admin('/admin/overview', {app_code: ''}));
    }

    async function loadApps() {
        app.view.renderAppsLoading();
        const data = await app.http.admin('/admin/apps/list', {page: 1, limit: 100});
        app.state.apps = data.apps || [];
        app.pruneOpenedAuthApps(app.state.apps.map((row) => row.app_code));
        pruneSelection('app');
        syncAppMetrics(app.state.apps);
        if (app.state.currentAppCode) {
            app.saveCurrentApp(app.state.currentAppCode);
        }
        app.view.renderApps(app.state.apps);
        if (app.state.currentView === 'authorization' && app.state.authSection === 'appConfig') {
            const row = currentAppRow();
            fillAppSettingsForm(row);
            fillAppApiForm(row);
            renderCurrentAppOperations(row);
        }
        renderVariableAppFilter();
        renderVariableAppPicker();
        syncHeaderLabel();
        updateSelectionState('app');
    }

    function syncAppMetrics(rows) {
        app.state.appMetrics.clear();
        rows.forEach((row) => {
            app.state.appMetrics.set(String(row.app_code), {
                cards_total: Number(row.cards_total || 0),
                devices_total: Number(row.devices_total || 0),
                sessions_active: Number(row.sessions_active || 0)
            });
        });
    }

    function renderVariableAppFilter() {
        const select = app.elements.filters.variableApp;
        if (!select) {
            return;
        }
        const currentValue = select.value;
        select.innerHTML = '<option value="">全部应用</option>' + app.state.apps.map((row) => (
            `<option value="${escapeHtml(row.id)}">${escapeHtml(row.name || row.app_code)}</option>`
        )).join('');
        select.value = app.state.apps.some((row) => String(row.id) === currentValue) ? currentValue : '';
        app.state.filters.variables.appId = select.value;
    }

    async function loadDashboardActivity() {
        const source = currentActivitySource();
        if (!source) {
            app.view.renderRecentActivity([], '');
            return;
        }
        app.view.renderRecentActivityLoading();
        const data = await app.http.admin('/admin/audits/list', {app_code: source.app_code, page: 1, limit: 10});
        app.view.renderRecentActivity(data.logs || [], source.name);
    }

    function currentActivitySource() {
        if (app.state.currentAppCode) {
            return currentAppRow();
        }
        return app.state.apps[0] || null;
    }

    function currentAppRow() {
        return app.state.apps.find((row) => row.app_code === app.state.currentAppCode) || null;
    }

    async function onCreateApp(form) {
        const payload = formData(form);
        validateAppPayload(payload);
        const data = await app.http.admin('/admin/apps/create', payload);
        form.reset();
        closeModal('app-modal');
        showPublicKeyModal(data.client_public_key || '');
        await loadApps();
        app.saveCurrentApp(app.state.apps.find((row) => row.app_code === data.app_code));
        syncHeaderLabel();
        app.view.showNotice('应用已添加，可进入授权管理');
    }

    function syncHeaderLabel() {
        if (app.state.currentView === 'account') {
            app.view.renderAdminProfile(app.state.adminProfile);
            return;
        }
        app.view.renderHeader();
    }

    async function changeMainView(view) {
        const normalizedView = normalizeMainView(view);
        activateMainView(normalizedView);
        if (normalizedView === 'variables') {
            await loadVariablesPage();
            return;
        }
        if (normalizedView === 'remoteApi') {
            await loadRemoteApiPage();
            return;
        }
        if (normalizedView === 'cloudStorage') {
            await loadCloudStoragePage();
            return;
        }
        if (normalizedView === 'apps') {
            await loadApps();
            return;
        }
        if (normalizedView === 'settings') {
            await loadSiteSettings();
            return;
        }
        if (normalizedView === 'dashboard') {
            await Promise.all([loadOverview(), loadDashboardActivity()]);
        }
    }

    function activateMainView(view) {
        app.view.setActiveView(normalizeMainView(view));
        syncHashView();
        syncSelectionBars();
    }

    function currentHashView() {
        const hashView = window.location.hash.replace(/^#/, '');
        if (hashView === 'remoteApiLogs') {
            app.state.remoteApiView = 'logs';
            return 'remoteApi';
        }
        if (hashView === 'remoteApi') {
            app.state.remoteApiView = 'tokens';
            return 'remoteApi';
        }
        if (hashView === 'cloudStorageConfig') {
            app.state.cloudStorageView = 'files';
            return 'cloudStorage';
        }
        if (hashView === 'cloudStorage') {
            app.state.cloudStorageView = 'files';
            return 'cloudStorage';
        }
        return hashViews.has(hashView) ? hashView : 'dashboard';
    }

    function normalizeMainView(view) {
        const normalizedView = String(view || '').trim();
        return mainViews.has(normalizedView) ? normalizedView : 'dashboard';
    }

    function syncHashView() {
        const view = normalizeMainView(app.state.currentView);
        if (view === 'remoteApi') {
            const remoteApiHash = app.state.remoteApiView === 'logs' ? '#remoteApiLogs' : '#remoteApi';
            if (window.location.hash !== remoteApiHash) {
                history.replaceState(null, '', `${window.location.pathname}${window.location.search}${remoteApiHash}`);
            }
            return;
        }
        if (view === 'cloudStorage') {
            if (window.location.hash !== '#cloudStorage') {
                history.replaceState(null, '', `${window.location.pathname}${window.location.search}#cloudStorage`);
            }
            return;
        }
        const nextHash = hashViews.has(view) && view !== 'dashboard' ? `#${view}` : '';
        if (window.location.hash === nextHash) {
            return;
        }
        history.replaceState(null, '', `${window.location.pathname}${window.location.search}${nextHash}`);
    }

    function onHashChange() {
        const previousRemoteApiView = app.state.remoteApiView;
        const view = currentHashView();
        if (view !== app.state.currentView) {
            runAsync(() => changeMainView(view));
            return;
        }
        if (view === 'remoteApi' && previousRemoteApiView !== app.state.remoteApiView) {
            runAsync(loadRemoteApiPage);
            return;
        }
        if (view === 'cloudStorage') {
            runAsync(loadCloudStoragePage);
        }
    }

    function activateAuthSection(section) {
        app.view.setAuthSection(section);
        syncSelectionBars();
    }

    function syncSelectionBars() {
        updateSelectionState('app');
        updateSelectionState('card');
        updateSelectionState('message');
        updateSelectionState('variable');
    }

    function openAdminAccount() {
        activateMainView('account');
        return loadAdminProfile();
    }

    async function clearRememberLogin() {
        if (!await confirmed('确认清除当前设备的记住登录状态？')) {
            return;
        }
        const data = await app.http.admin('/admin/profile/clear-remember', {});
        app.view.renderAdminProfile(data.profile || app.state.adminProfile);
        resetAdminProfileForm(false);
        app.view.showNotice('记住登录已清除');
    }

    function logoutAdmin() {
        clearAdminSessionState();
        window.location.replace(`${app.state.loginUrl}?logout=1`);
    }

    function resetAdminProfileForm(clearSecrets = true) {
        app.view.renderAdminProfile(app.state.adminProfile);
        const form = app.elements.adminProfileForm;
        if (!form || !clearSecrets) {
            return;
        }
        form.elements.current_password.value = '';
        form.elements.new_password.value = '';
        form.elements.confirm_password.value = '';
    }

    async function onSaveAdminProfile(form) {
        const payload = adminProfilePayload(form);
        const data = await app.http.admin('/admin/profile/update', payload);
        if (!data.relogin_required) {
            return;
        }
        app.view.showNotice('账号资料已更新，请重新登录');
        clearAdminSessionState();
        window.setTimeout(() => {
            window.location.replace(app.state.loginUrl);
        }, 900);
    }

    function adminProfilePayload(form) {
        const payload = {
            username: form.username.value.trim(),
            current_password: form.current_password.value,
            new_password: form.new_password.value,
            confirm_password: form.confirm_password.value
        };
        validateAdminProfilePayload(payload);
        return payload;
    }

    function validateAdminProfilePayload(payload) {
        if (!/^[A-Za-z0-9_.@-]{3,32}$/.test(payload.username)) {
            throw new Error('管理员账号格式不正确');
        }
        if (payload.current_password.length < 1) {
            throw new Error('请输入当前密码');
        }
        if (payload.new_password === '' && payload.confirm_password === '') {
            return;
        }
        if (payload.new_password !== payload.confirm_password) {
            throw new Error('两次输入的新密码不一致');
        }
        if (payload.new_password.length < 8 || payload.new_password.length > 72) {
            throw new Error('新密码长度必须在 8 到 72 个字符之间');
        }
    }

    function clearAdminSessionState() {
        app.state.sessionToken = '';
        app.state.sessionKey = '';
    }

    async function onCreateCards(form) {
        requireCurrentApp();
        const payload = Object.assign(appCodePayload(), cardCreatePayload(form));
        const data = await app.http.admin('/admin/cards/create', payload);
        form.reset();
        resetDurationInput(form);
        closeModal('card-modal');
        openModal('card-result-modal');
        app.elements.cardsOutput.value = data.cards.join('\n');
        await loadCards();
        app.view.showNotice(cardCreateNotice(data));
    }

    async function onImportCards(form) {
        requireCurrentApp();
        const payload = Object.assign(appCodePayload(), cardImportPayload(form));
        const data = await app.http.admin('/admin/cards/import', payload);
        form.reset();
        resetDurationInput(form);
        closeModal('card-import-modal');
        openModal('card-result-modal');
        app.elements.cardsOutput.value = data.cards.join('\n');
        await loadCards();
        app.view.showNotice(cardCreateNotice(data));
    }

    async function onAdjustCardTime(form) {
        const direction = form.elements.direction.value;
        const payload = {
            direction,
            duration_seconds: durationFromForm(form)
        };
        assertRange(payload.duration_seconds, 3600, maxCardDurationSeconds, '有效时长超出范围');
        const batchCardIds = csvIdValues(form.elements.card_ids.value);
        if (batchCardIds.length > 0) {
            payload.card_ids = batchCardIds;
            await app.http.admin('/admin/cards/batch-adjust-time', Object.assign(appCodePayload(), payload));
        } else {
            if (direction === 'reset' && !await confirmed(`确认将该卡密重置为未激活计时，并把总时长设为 ${app.view.durationText(payload.duration_seconds)}？设备绑定会保留，当前会话会撤销。`)) {
                return;
            }
            payload.card_id = idValue(form.elements.card_id.value);
            await app.http.admin('/admin/cards/adjust-time', payload);
        }
        closeModal('time-modal');
        await loadCards();
        app.view.showNotice(direction === 'reset' ? '卡密时长已重置' : '卡密时长已调整');
    }

    async function onCardRangeOperation(form) {
        requireCurrentApp();
        const payload = cardRangeOperationPayload(form);
        if (!await confirmed(cardRangeConfirmText(payload))) {
            return;
        }
        const response = await app.http.admin('/admin/cards/range-operation', payload);
        closeModal('card-range-modal');
        await loadCards();
        app.view.showNotice(cardRangeResultText(response));
    }

    async function onSaveAppSettings(form) {
        const row = currentAppRow();
        if (!row) {
            throw new Error('当前应用不存在');
        }
        const payload = appSettingsPayload(form, row);
        await app.http.admin('/admin/apps/update', payload);
        await loadApps();
        fillAppSettingsForm(currentAppRow());
        renderCurrentAppOperations(currentAppRow());
        app.view.showNotice('应用设置已保存');
    }

    async function onSaveAppApi(form) {
        const row = currentAppRow();
        if (!row) {
            throw new Error('当前应用不存在');
        }
        await app.http.admin('/admin/apps/api/update', appApiPayload(form, row));
        await loadApps();
        fillAppApiForm(currentAppRow());
        app.view.showNotice('接口控制已保存');
    }

    async function onSaveConfig(form) {
        requireCurrentApp();
        const payload = Object.assign(appCodePayload(), {
            version: form.elements.version.value.trim(),
            download_url: form.elements.download_url.value.trim(),
            notice: form.elements.notice.value.trim(),
            force_update: form.elements.force_update.checked,
        });
        assertSafeText(payload.version, 40, '版本格式错误');
        assertSafeText(payload.download_url, 255, '下载地址格式错误');
        assertSafeTextBlock(payload.notice, 2000, '公告格式错误');
        await app.http.admin('/admin/config/set', payload);
        app.view.showNotice('远程配置已保存');
    }

    async function changeAuthSection(section) {
        activateAuthSection(section);
        await refreshAuthData();
    }

    async function refreshAuthData() {
        requireCurrentApp();
        await ({
            cards: loadCards,
            appConfig: loadAppConfigPanel,
            integration: loadIntegrationPanel,
            messages: loadMessages
        })[app.state.authSection]();
    }

    async function enterAuthorizationApp(appCode, section) {
        const selected = app.state.apps.find((row) => row.app_code === appCode);
        if (!selected) {
            throw new Error('应用不存在');
        }
        app.saveCurrentApp(selected);
        clearAppScopedState();
        activateAuthSection(section);
        activateMainView('authorization');
        await refreshAuthData();
    }

    async function switchAuthorizationApp(appCode) {
        const section = app.state.authSection;
        if (appCode === app.state.currentAppCode) {
            return;
        }
        await enterAuthorizationApp(appCode, section);
    }

    async function closeAuthorizationApp(appCode) {
        const normalizedCode = String(appCode || '').trim();
        if (!normalizedCode || !app.state.openedAuthAppCodes.includes(normalizedCode)) {
            return;
        }
        const nextAppCode = nextOpenedAuthAppCode(normalizedCode);
        const closingCurrentApp = normalizedCode === app.state.currentAppCode;
        app.closeAuthApp(normalizedCode);
        if (!closingCurrentApp) {
            syncHeaderLabel();
            return;
        }
        if (nextAppCode) {
            await enterAuthorizationApp(nextAppCode, app.state.authSection);
            return;
        }
        app.saveCurrentApp('');
        clearAppScopedState();
        activateMainView('apps');
        activateAuthSection('cards');
    }

    function nextOpenedAuthAppCode(closedAppCode) {
        const openedCodes = app.state.openedAuthAppCodes;
        const closedIndex = openedCodes.indexOf(closedAppCode);
        if (closedIndex < 0) {
            return '';
        }
        const remainingCodes = openedCodes.filter((appCode) => appCode !== closedAppCode);
        return remainingCodes[closedIndex] || remainingCodes[closedIndex - 1] || '';
    }

    function clearAppScopedState() {
        app.state.selectedCardIds.clear();
        app.state.selectedMessageIds.clear();
        app.state.selectedCardId = '';
        app.state.selectedCardDevices = [];
        app.state.cards = [];
        app.state.messages = [];
        app.state.remoteConfig = null;
        app.state.integration = null;
    }

    function isInteractiveAppCardTarget(target) {
        return Boolean(target.closest('button, a, input, select, textarea, label, [data-action]'));
    }

    async function loadCards() {
        setTableLoading(app.elements.tables.cards, 10);
        const data = await app.http.admin('/admin/cards/list', cardListPayload());
        app.state.cards = data.cards || [];
        app.state.cardPagination = cardPaginationFromResponse(data);
        pruneSelection('card');
        app.view.renderCardPager(app.state.cardPagination);
        await renderFilteredCards();
    }

    function cardPaginationFromResponse(data) {
        const current = app.state.cardPagination;
        const pageSize = numberValue(data.limit ?? current.pageSize);
        const total = numberValue(data.total ?? 0);
        const totalPages = Math.max(1, numberValue(data.total_pages ?? Math.ceil(total / Math.max(1, pageSize))));
        return {
            page: Math.min(Math.max(1, numberValue(data.page ?? current.page)), totalPages),
            pageSize: Math.max(1, pageSize),
            total,
            totalPages
        };
    }

    async function changeCardPage(offset) {
        const pagination = app.state.cardPagination;
        const nextPage = Math.min(pagination.totalPages, Math.max(1, pagination.page + offset));
        if (nextPage === pagination.page) {
            return;
        }
        app.state.cardPagination.page = nextPage;
        await loadCards();
    }

    function onCardPageSizeChange() {
        app.state.cardPagination.pageSize = numberValue(app.elements.filters.cardPageSize.value);
        resetCardPage();
        runAsync(loadCards);
    }

    function resetCardPage() {
        app.state.cardPagination.page = 1;
    }

    async function loadMessages() {
        setTableLoading(app.elements.tables.messages, 9);
        const data = await app.http.admin('/admin/messages/list', messageListPayload());
        app.state.messages = data.messages || [];
        pruneSelection('message');
        app.view.renderMessages(app.state.messages);
        updateSelectionState('message');
    }

    async function loadAppConfigPanel() {
        const row = currentAppRow();
        if (!row) {
            throw new Error('当前应用不存在');
        }
        app.view.setAppConfigView(app.state.appConfigView);
        fillAppSettingsForm(row);
        fillAppApiForm(row);
        renderCurrentAppOperations(row);
        await loadRemoteConfigState();
        fillConfigForm(app.state.remoteConfig);
    }

    async function loadVariablesPage() {
        setTableLoading(app.elements.tables.variables, 8);
        const data = await app.http.admin('/admin/variables/list', variableListPayload());
        app.state.remoteVariables = normalizeRemoteVariables(Array.isArray(data.variables) ? data.variables : []);
        pruneSelection('variable');
        renderRemoteVariables();
    }

    async function loadRemoteApiPage() {
        app.view.setRemoteApiView(app.state.remoteApiView);
        if (app.state.remoteApiView === 'logs') {
            await loadRemoteApiLogsPage();
            return;
        }
        await loadRemoteApiTokens();
    }

    async function loadRemoteApiLogsPage() {
        await loadRemoteApiTokens();
        await loadRemoteApiLogs();
    }

    async function loadRemoteApiTokens() {
        setTableLoading(app.elements.tables.remoteApiTokens, 7);
        const data = await app.http.admin('/admin/remote-api/tokens/list', remoteApiTokenListPayload());
        app.state.remoteApiTokens = normalizeRemoteApiTokens(Array.isArray(data.tokens) ? data.tokens : []);
        renderRemoteApiLogTokenFilter();
        app.view.renderRemoteApiTokens(app.state.remoteApiTokens);
    }

    async function loadRemoteApiLogs() {
        setTableLoading(app.elements.tables.remoteApiLogs, 5);
        const data = await app.http.admin('/admin/remote-api/logs/list', remoteApiLogListPayload());
        app.state.remoteApiLogs = normalizeRemoteApiLogs(Array.isArray(data.logs) ? data.logs : []);
        app.view.renderRemoteApiLogs(app.state.remoteApiLogs);
    }

    async function loadCloudStoragePage() {
        app.view.setCloudStorageView('files');
        await loadCloudSummary();
        await loadCloudFiles();
    }

    async function loadCloudSummary() {
        const data = await app.http.admin('/admin/cloud-storage/summary', {});
        app.state.cloudStorageSummary = data;
        app.state.cloudDownloadToken = data.download_token || null;
        app.view.renderCloudSummary(data);
    }

    async function loadCloudFiles() {
        setTableLoading(app.elements.tables.cloudFiles, 7);
        const data = await app.http.admin('/admin/cloud-storage/files/list', cloudFileListPayload());
        app.state.cloudFiles = Array.isArray(data.files) ? data.files.map(normalizeCloudFile) : [];
        app.view.renderCloudFiles(app.state.cloudFiles);
    }

    async function loadCloudConfig() {
        const data = await app.http.admin('/admin/cloud-storage/config/get', {});
        app.state.cloudStorageConfigs = Array.isArray(data.configs) ? data.configs : [];
        app.view.renderCloudConfigForm(app.state.cloudStorageConfigs, data.default_config || {});
    }

    async function openCloudConfigModal() {
        openModal('cloud-config-modal', '#cloud-storage-config-form [name="provider"]');
        await loadCloudConfig();
    }

    async function openCloudUploadModal() {
        if (!app.state.cloudStorageSummary) {
            await loadCloudSummary();
        }
        const modal = openModal('cloud-upload-modal', '#cloud-upload-file');
        const form = modal.querySelector('#cloud-upload-form');
        if (form) {
            form.reset();
        }
        app.view.renderCloudUploadTarget(app.state.cloudStorageSummary);
        app.view.renderCloudUploadHash('等待选择文件');
    }

    async function openCloudTokenModal() {
        const data = await app.http.admin('/admin/cloud-storage/download-token/get', {});
        app.state.cloudDownloadToken = data.download_token || null;
        openModal('cloud-token-modal');
        app.view.renderCloudDownloadToken(app.state.cloudDownloadToken);
    }

    async function refreshCloudDownloadToken() {
        if (!await confirmed('确认刷新云存储下载 Token？刷新后旧 Token 立即失效。')) {
            return;
        }
        const data = await app.http.admin('/admin/cloud-storage/download-token/refresh', {});
        app.state.cloudDownloadToken = data.download_token || null;
        app.view.renderCloudDownloadToken(app.state.cloudDownloadToken);
        await loadCloudSummary();
        app.view.showNotice('下载 Token 已刷新');
    }

    async function setCloudDownloadTokenStatus(node) {
        const status = numberValue(node.dataset.status);
        const data = await app.http.admin('/admin/cloud-storage/download-token/status', {status});
        app.state.cloudDownloadToken = data.download_token || null;
        app.view.renderCloudDownloadToken(app.state.cloudDownloadToken);
        await loadCloudSummary();
        app.view.showNotice(status === 1 ? '下载 Token 已启用' : '下载 Token 已禁用');
    }

    async function copyCloudDownloadToken() {
        const token = app.state.cloudDownloadToken?.token || '';
        if (!token) {
            throw new Error('当前没有可复制的下载 Token');
        }
        await navigator.clipboard.writeText(token);
        app.view.showNotice('下载 Token 已复制');
    }

    async function enabledCloudDownloadToken() {
        if (!app.state.cloudDownloadToken?.token) {
            const data = await app.http.admin('/admin/cloud-storage/download-token/get', {});
            app.state.cloudDownloadToken = data.download_token || null;
        }
        const token = app.state.cloudDownloadToken || {};
        if (numberValue(token.status) !== 1 || !token.token) {
            throw new Error('请先启用云存储下载 Token');
        }
        return token.token;
    }

    async function syncCloudUploadFile(input) {
        const file = input.files?.[0] || null;
        if (!file) {
            app.view.renderCloudUploadHash('等待选择文件');
            return;
        }
        app.view.renderCloudUploadHash(`正在计算 SHA256：${file.name}`);
        const sha256 = await sha256File(file);
        input.dataset.sha256 = sha256;
        app.view.renderCloudUploadHash(`SHA256：${sha256}`);
    }

    async function onUploadCloudFile(form) {
        const file = form.elements.file.files?.[0] || null;
        if (!file) {
            throw new Error('请选择要上传的文件');
        }
        const sha256 = form.elements.file.dataset.sha256 || await sha256File(file);
        const ticket = await app.http.admin('/admin/cloud-storage/upload-ticket/create', {
            original_name: file.name,
            size_bytes: file.size,
            sha256,
            mime_type: file.type || 'application/octet-stream',
            remark: form.elements.remark.value.trim()
        });
        const body = new FormData();
        body.append('ticket', ticket.ticket || '');
        body.append('file', file, file.name);
        await app.http.adminUpload('/admin/cloud-storage/files/upload', body);
        closeModal('cloud-upload-modal');
        await loadCloudStoragePage();
        app.view.showNotice('文件已上传');
    }

    async function onSaveCloudConfig(form) {
        const payload = cloudConfigPayload(form);
        await app.http.admin('/admin/cloud-storage/config/save', payload);
        closeModal('cloud-config-modal');
        await loadCloudStoragePage();
        app.view.showNotice('云存储配置已保存');
    }

    async function testCloudConfig() {
        const form = app.elements.cloudStorageConfigForm;
        if (!form) {
            throw new Error('云存储配置表单不存在');
        }
        const result = await app.http.admin('/admin/cloud-storage/config/test', cloudConfigPayload(form));
        await loadCloudConfig();
        app.view.showNotice(result.message || '连接测试完成');
    }

    async function copyCloudFileLink(node) {
        const row = cloudFileById(node.dataset.id);
        const url = new URL(row.external_download_path || '', window.location.origin);
        url.searchParams.set('download_token', await enabledCloudDownloadToken());
        await navigator.clipboard.writeText(url.href);
        app.view.showNotice('下载链接已复制');
    }

    function showCloudFileDetail(node) {
        const row = cloudFileById(node.dataset.id);
        openModal('cloud-file-detail-modal');
        app.view.renderCloudFileDetail(row);
    }

    async function deleteCloudFile(node) {
        const row = cloudFileById(node.dataset.id);
        if (!await confirmed(`确认删除文件 ${row.original_name || row.file_key}？`)) {
            return;
        }
        await app.http.admin('/admin/cloud-storage/files/delete', {file_id: row.id});
        await loadCloudStoragePage();
        app.view.showNotice('文件已删除');
    }

    async function loadIntegrationPanel() {
        requireCurrentApp();
        app.view.renderIntegrationLoading();
        const data = await app.http.admin('/admin/apps/integration', {
            app_code: app.state.currentAppCode,
            api_url: absoluteApiUrl()
        });
        app.state.integration = data;
        app.view.renderIntegrationDocs(data);
    }

    async function openIntegrationSection() {
        activateAuthSection('integration');
        await loadIntegrationPanel();
    }

    function openAppConfigView(view) {
        if (!['settings', 'remote', 'api', 'operations'].includes(String(view))) {
            throw new Error('应用配置分组不存在');
        }
        app.view.setAppConfigView(String(view));
    }

    async function openRemoteApiView(view) {
        const normalizedView = String(view);
        if (!['tokens', 'logs'].includes(normalizedView)) {
            throw new Error('远程 API 分组不存在');
        }
        app.view.setRemoteApiView(normalizedView);
        syncHashView();
        await loadRemoteApiPage();
    }

    async function loadRemoteConfigState() {
        const data = await app.http.admin('/admin/config/get', appCodePayload());
        app.state.remoteConfig = data.config || null;
        return data;
    }

    async function cleanupNonces() {
        if (!await confirmed('确认清理过期 nonce 和无效会话？')) {
            return;
        }
        const data = await app.http.admin('/admin/maintenance/cleanup-nonces', {});
        app.view.showNotice(`已清理 ${data.deleted_nonces} 条 nonce，${data.deleted_sessions} 条会话`);
        await loadOverview();
    }

    async function copySecret() {
        const secret = app.elements.appSecret?.textContent || '';
        if (!secret) {
            throw new Error('没有可复制的内容');
        }
        await navigator.clipboard.writeText(secret);
        app.view.showNotice('内容已复制');
    }

    async function onCreateRemoteApiToken(form) {
        if (!form) {
            throw new Error('远程 API Token 表单不存在');
        }
        const payload = remoteApiTokenFormPayload(form);
        const data = await app.http.admin('/admin/remote-api/tokens/create', payload);
        const token = data.token || {};
        showSecretModal(`accessKey=${token.access_key || ''}\nsecret=${data.secret || ''}`, '', {
            title: '远程 API Token',
            secretLabel: '可复制凭据：',
            hidePublicKey: true
        });
        form.reset();
        closeModal('remote-api-token-modal');
        await loadRemoteApiPage();
        app.view.showNotice('远程 API Token 已创建');
    }

    async function setRemoteApiTokenStatus(node) {
        const token = remoteApiTokenById(node.dataset.id);
        const status = numberValue(node.dataset.status);
        if (status === 0 && !await confirmed(`确认禁用远程 API Token ${token.name}？`)) {
            return;
        }
        await app.http.admin('/admin/remote-api/tokens/status', {token_id: token.id, status});
        await reloadCurrentRemoteApiView();
        app.view.showNotice(status === 1 ? '远程 API Token 已启用' : '远程 API Token 已禁用');
    }

    async function showRemoteApiTokenSecret(node) {
        const token = remoteApiTokenById(node.dataset.id);
        const data = await app.http.admin('/admin/remote-api/tokens/secret', {token_id: token.id});
        const tokenView = data.token || token;
        showSecretModal(`accessKey=${tokenView.access_key || token.access_key || ''}\nsecret=${data.secret || ''}`, '', {
            title: `远程 API Token · ${tokenView.name || token.name || ''}`,
            secretLabel: '可复制凭据：',
            hidePublicKey: true
        });
    }

    async function deleteRemoteApiToken(node) {
        const token = remoteApiTokenById(node.dataset.id);
        if (!await confirmed(`确认删除远程 API Token ${token.name}？`)) {
            return;
        }
        await app.http.admin('/admin/remote-api/tokens/delete', {token_id: token.id});
        await reloadCurrentRemoteApiView();
        app.view.showNotice('远程 API Token 已删除');
    }

    async function deleteRemoteApiLog(node) {
        const log = remoteApiLogById(node.dataset.id);
        if (!await confirmed(`确认删除这条调用日志？${app.view.remoteApiActionText(log)}`)) {
            return;
        }
        const result = await app.http.admin('/admin/remote-api/logs/delete', {log_id: log.id});
        await loadRemoteApiLogs();
        app.view.showNotice(`已删除调用日志 ${Number(result.deleted || 0)} 条`);
    }

    async function clearRemoteApiLogs() {
        if (!await confirmed('确认清空全部远程 API 调用日志？这个操作不可恢复。')) {
            return;
        }
        const result = await app.http.admin('/admin/remote-api/logs/clear', {confirm: 'CLEAR_REMOTE_API_LOGS'});
        await loadRemoteApiLogs();
        app.view.showNotice(`已清空调用日志 ${Number(result.deleted || 0)} 条`);
    }

    function showRemoteApiLogDetail(node) {
        const log = remoteApiLogById(node.dataset.id);
        openModal('remote-api-log-detail-modal');
        app.view.renderRemoteApiLogDetail(log);
    }

    async function reloadCurrentRemoteApiView() {
        if (app.state.remoteApiView === 'logs') {
            await loadRemoteApiLogsPage();
            return;
        }
        await loadRemoteApiPage();
    }

    async function copyIntegrationParams() {
        if (!app.state.integration?.app) {
            await loadIntegrationPanel();
        }
        await navigator.clipboard.writeText(integrationParamsText(app.state.integration));
        app.view.showNotice('应用参数已复制');
    }

    function integrationParamsText(data) {
        const appInfo = data?.app || {};
        return JSON.stringify({
            api_url: String(data?.api_url || ''),
            app_code: String(appInfo.app_code || ''),
            app_name: String(appInfo.name || ''),
            api_token: String(appInfo.api_token || ''),
            app_version: String(appInfo.app_version || ''),
            api_success_code: Number(appInfo.api_success_code || 0),
            client_auth_mode: String(appInfo.client_auth_mode || ''),
            client_crypto_alg: String(appInfo.client_crypto_alg || ''),
            client_public_key: String(appInfo.client_public_key || ''),
            heartbeat_interval: Number(appInfo.heartbeat_interval || 0),
            api_routes: integrationRouteParams(appInfo.api_routes || [])
        }, null, 2);
    }

    function integrationRouteParams(routes) {
        return (Array.isArray(routes) ? routes : []).map((route) => ({
            route: String(route.route || ''),
            enabled: Number(route.enabled ?? 1) === 1,
            call_id: String(route.call_id || '')
        }));
    }

    async function copyGeneratedCards() {
        await navigator.clipboard.writeText(app.elements.cardsOutput.value);
        app.view.showNotice('卡密已复制');
    }

    function exportGeneratedCards() {
        const blob = new Blob([app.elements.cardsOutput.value], {type: 'text/plain;charset=utf-8'});
        const url = URL.createObjectURL(blob);
        const link = document.createElement('a');
        link.href = url;
        link.download = `cards-${Date.now()}.txt`;
        link.click();
        URL.revokeObjectURL(url);
    }

    async function exportCurrentCards() {
        requireCurrentApp();
        const payload = appCodePayload({
            status: app.state.filters.cards.status,
            keyword: app.state.filters.cards.search,
            duration_category: app.state.filters.cards.durationCategory
        });
        const selected = [...app.state.selectedCardIds];
        if (selected.length > 0) {
            payload.card_ids = selected;
        }
        const file = await app.http.admin('/admin/cards/export', payload);
        downloadBase64File(file.content_base64, file.filename, file.mime || 'text/plain;charset=utf-8');
        const skipped = Number(file.skipped_unrecoverable || 0);
        const message = skipped > 0
            ? `已导出 ${Number(file.rows || 0)} 张卡密，跳过 ${skipped} 条不可恢复旧数据`
            : `已导出 ${Number(file.rows || 0)} 张卡密`;
        app.view.showNotice(message);
    }

    function downloadBase64File(contentBase64, filename, mime) {
        if (typeof contentBase64 !== 'string' || contentBase64 === '') {
            throw new Error('文件内容为空');
        }

        const binary = atob(contentBase64);
        const chunks = [];
        for (let offset = 0; offset < binary.length; offset += 8192) {
            const slice = binary.slice(offset, offset + 8192);
            const bytes = new Uint8Array(slice.length);
            for (let index = 0; index < slice.length; index += 1) {
                bytes[index] = slice.charCodeAt(index);
            }
            chunks.push(bytes);
        }

        const blob = new Blob(chunks, {type: mime || 'application/octet-stream'});
        const url = URL.createObjectURL(blob);
        const link = document.createElement('a');
        link.href = url;
        link.download = filename || `license-auth-sdk-${Date.now()}.zip`;
        document.body.appendChild(link);
        link.click();
        link.remove();
        window.setTimeout(() => URL.revokeObjectURL(url), 0);
    }

    async function sha256File(file) {
        const bytes = new Uint8Array(await crypto.subtle.digest('SHA-256', await file.arrayBuffer()));
        return [...bytes].map((value) => value.toString(16).padStart(2, '0')).join('');
    }

    async function setAppStatus(node) {
        const disabling = Number(node.dataset.status) === 0;
        if (disabling && !await confirmed('确认停用该应用？停用后客户端请求会失败。')) {
            return;
        }
        await app.http.admin('/admin/apps/status', actionPayload(node, 'app_code'));
        await refreshAll({silent: true});
        app.view.showNotice('应用状态已更新');
    }

    async function downloadAppSdk(appCode, sdkType) {
        validateAppCode(appCode);
        const sdk = await app.http.admin('/admin/apps/sdk', {
            app_code: appCode,
            api_url: absoluteApiUrl(),
            sdk_type: sdkType
        });
        downloadBase64File(sdk.content_base64, sdk.filename, sdk.mime || 'application/zip');
        app.view.showNotice(`${sdkTypeLabel(sdkType)} SDK 已开始下载`);
    }

    async function downloadCurrentAppSdk(sdkType) {
        requireCurrentApp();
        closeSdkDownloadModal();
        await downloadAppSdk(app.state.currentAppCode, sdkType);
    }

    async function downloadSelectedSdk() {
        const sdkType = app.elements.sdkTypeSelect?.value || 'cpp';
        await downloadCurrentAppSdk(sdkType);
    }

    function currentAppActionNode() {
        const row = currentAppRow();
        if (!row) {
            throw new Error('当前应用不存在');
        }
        return {dataset: {id: String(row.id), app: row.app_code}};
    }

    function generateCurrentAppKeyPair() {
        return generateKeyPair(currentAppActionNode());
    }

    function deleteCurrentApp() {
        return deleteApp(currentAppActionNode());
    }

    async function generateKeyPair(node) {
        const row = app.state.apps.find((item) => item.app_code === node.dataset.app);
        if (!row) {
            throw new Error('应用不存在');
        }
        const data = await app.http.admin('/admin/apps/generate-keypair', {
            app_code: row.app_code,
            client_crypto_alg: row.client_crypto_alg || 'rsa_oaep_aes_256_gcm'
        });
        showPublicKeyModal(data.client_public_key);
        app.view.showNotice('客户端密钥对已重新生成');
        await loadApps();
    }

    async function deleteApp(node) {
        if (!await confirmed('确认删除该应用及其全部授权数据？')) {
            return;
        }
        const deletingCurrentApp = node.dataset.app === app.state.currentAppCode;
        await app.http.admin('/admin/apps/delete', {app_ids: [idValue(node.dataset.id)]});
        await refreshAll({silent: true});
        if (deletingCurrentApp) {
            activateMainView('apps');
            activateAuthSection('cards');
        }
        app.view.showNotice('应用已删除');
    }

    async function batchDisableApps() {
        closeAppBatchModal();
        const appIds = selectedIds('app', '请选择应用');
        if (!await confirmed(`确认停用 ${appIds.length} 个应用？`)) {
            return;
        }
        await app.http.admin('/admin/apps/batch-status', {app_ids: appIds, status: 0});
        await loadApps();
    }

    async function batchEnableApps() {
        closeAppBatchModal();
        const appIds = selectedIds('app', '请选择应用');
        if (!await confirmed(`确认启用 ${appIds.length} 个应用？`)) {
            return;
        }
        await app.http.admin('/admin/apps/batch-status', {app_ids: appIds, status: 1});
        await loadApps();
    }

    async function batchDeleteApps() {
        closeAppBatchModal();
        const appIds = selectedIds('app', '请选择应用');
        if (!await confirmed(`确认删除 ${appIds.length} 个应用？`)) {
            return;
        }
        await app.http.admin('/admin/apps/delete', {app_ids: appIds});
        await refreshAll({silent: true});
    }

    async function setCardStatus(node) {
        closeCardActionModal();
        const disabling = Number(node.dataset.status) === 2;
        if (disabling && !await confirmed('确认禁用该卡密？')) {
            return;
        }
        await app.http.admin('/admin/cards/status', {card_id: idValue(node.dataset.id), status: numberValue(node.dataset.status)});
        await loadCards();
    }

    async function deleteCard(node) {
        closeCardActionModal();
        if (!await confirmed('确认删除该卡密？')) {
            return;
        }
        await app.http.admin('/admin/cards/delete', {app_code: node.dataset.app, card_ids: [idValue(node.dataset.id)]});
        await loadCards();
    }

    async function resetCardUses(node) {
        closeCardActionModal();
        if (!await confirmed('确认将该次数卡剩余次数重置为总次数？')) {
            return;
        }
        await app.http.admin('/admin/cards/reset-uses', {card_id: idValue(node.dataset.id)});
        await loadCards();
        app.view.showNotice('次数卡已重置');
    }

    async function batchDisableCards() {
        closeCardBatchModal();
        const cardIds = selectedIds('card', '请选择卡密');
        if (!await confirmed(`确认禁用 ${cardIds.length} 张卡密？`)) {
            return;
        }
        await app.http.admin('/admin/cards/batch-status', {app_code: app.state.currentAppCode, card_ids: cardIds, status: 2});
        await loadCards();
    }

    async function batchEnableCards() {
        closeCardBatchModal();
        const cardIds = selectedIds('card', '请选择卡密');
        if (!await confirmed(`确认启用 ${cardIds.length} 张卡密？`)) {
            return;
        }
        await app.http.admin('/admin/cards/batch-status', {app_code: app.state.currentAppCode, card_ids: cardIds, status: 0});
        await loadCards();
    }

    async function batchDeleteCards() {
        closeCardBatchModal();
        const cardIds = selectedIds('card', '请选择卡密');
        if (!await confirmed(`确认删除 ${cardIds.length} 张卡密？`)) {
            return;
        }
        await app.http.admin('/admin/cards/delete', {app_code: app.state.currentAppCode, card_ids: cardIds});
        await loadCards();
    }

    async function batchResetCardUses() {
        closeCardBatchModal();
        const cardIds = selectedIds('card', '请选择卡密');
        if (!await confirmed('确认重置已选卡密中的次数卡？')) {
            return;
        }
        const response = await app.http.admin('/admin/cards/batch-reset-uses', {app_code: app.state.currentAppCode, card_ids: cardIds});
        await loadCards();
        app.view.showNotice(`已重置 ${Number(response.updated || 0)} 张次数卡`);
    }

    async function batchSetCardDevicesStatus(status) {
        closeCardBatchModal();
        const cardIds = selectedIds('card', '请选择卡密');
        const disabling = Number(status) === 0;
        const label = disabling ? '禁用' : '启用';
        if (!await confirmed(`确认${label}已选卡密绑定的全部设备？次数卡会自动跳过。`)) {
            return;
        }
        const response = await app.http.admin('/admin/cards/devices/batch-status', {
            app_code: app.state.currentAppCode,
            card_ids: cardIds,
            status: disabling ? 0 : 1,
        });
        await loadCards();
        app.view.showNotice(`已${label} ${Number(response.updated_devices || 0)} 台设备`);
    }

    async function batchUnbindCardDevices() {
        closeCardBatchModal();
        const cardIds = selectedIds('card', '请选择卡密');
        if (!await confirmed('确认清空已选卡密绑定的全部设备？次数卡会自动跳过。')) {
            return;
        }
        const response = await app.http.admin('/admin/cards/devices/batch-unbind', {
            app_code: app.state.currentAppCode,
            card_ids: cardIds,
        });
        await loadCards();
        app.view.showNotice(`已清空 ${Number(response.unbound_devices || 0)} 台绑定设备`);
    }

    async function unbindCardDevice(node) {
        if (!await confirmed('确认解绑该设备？')) {
            return;
        }
        await app.http.admin('/admin/cards/devices/unbind', {device_id: idValue(node.dataset.deviceId)});
        await reloadSelectedCardDevices(true);
        await loadCards();
    }

    async function unbindAllCardDevices(node) {
        closeCardActionModal();
        if (!await confirmed('确认解绑该卡密下全部设备？')) {
            return;
        }
        await app.http.admin('/admin/cards/devices/unbind-all', {app_code: node.dataset.app, card_id: idValue(node.dataset.id)});
        await reloadSelectedCardDevices(true);
        await loadCards();
    }

    async function setDeviceStatus(node) {
        const disabling = Number(node.dataset.status) === 0;
        if (disabling && !await confirmed('确认禁用该设备？')) {
            return;
        }
        await app.http.admin('/admin/devices/status', {
            app_code: node.dataset.app,
            device_id: idValue(node.dataset.id),
            status: numberValue(node.dataset.status),
        });
        await reloadSelectedCardDevices(true);
        await loadCards();
    }

    async function renderFilteredCards() {
        const rows = filterCards(app.state.cards);
        pruneSelectionToRows('card', rows);
        app.view.renderCards(rows);
        updateSelectionState('card');
    }

    function renderSelectedCardDevices() {
        const row = selectedCardRow();
        if (!row) {
            app.view.renderSelectedCardEmpty();
            return;
        }
        app.view.renderSelectedCard(row, filterSelectedCardDevices(app.state.selectedCardDevices));
    }

    function filterCards(rows) {
        return rows;
    }

    function cardListPayload() {
        const filters = app.state.filters.cards;
        const pagination = app.state.cardPagination;
        return pagingPayload({
            page: pagination.page,
            limit: pagination.pageSize,
            status: filters.status,
            duration_category: filters.durationCategory,
            keyword: filters.search
        });
    }

    function variableListPayload() {
        const filters = app.state.filters.variables;
        return {
            keyword: filters.search,
            scope: filters.scope,
            status: filters.status,
            app_id: filters.appId
        };
    }

    function remoteApiTokenListPayload() {
        const filters = app.state.filters.remoteApiTokens;
        return {
            keyword: filters.search,
            status: filters.status,
            page: 1,
            limit: 100
        };
    }

    function remoteApiLogListPayload() {
        const filters = app.state.filters.remoteApiLogs;
        return {
            keyword: filters.search,
            status: filters.status,
            token_id: filters.tokenId,
            page: 1,
            limit: 100
        };
    }

    function cloudFileListPayload() {
        const filters = app.state.filters.cloudFiles;
        return {
            keyword: filters.search,
            provider: filters.provider,
            status: filters.status,
            page: 1,
            limit: 100
        };
    }

    function cloudConfigPayload(form) {
        const provider = form.elements.provider.value;
        const payload = {
            provider,
            status: numberValue(form.elements.status.value),
            bucket: form.elements.bucket.value.trim(),
            region: form.elements.region.value.trim(),
            endpoint: form.elements.endpoint.value.trim(),
            access_key: form.elements.access_key.value.trim(),
            secret: form.elements.secret.value,
            path_prefix: form.elements.path_prefix.value.trim(),
            custom_domain: form.elements.custom_domain.value.trim(),
            max_file_size: cloudSizeBytes(form),
            allowed_extensions: form.elements.allowed_extensions.value.trim(),
            signed_url_ttl_seconds: cloudTtlSeconds(form),
            set_default: form.elements.set_default.checked ? 1 : 0
        };
        if (provider === 'local') {
            payload.bucket = '';
            payload.region = '';
            payload.endpoint = '';
            payload.access_key = '';
            payload.secret = '';
            payload.path_prefix = '';
            payload.custom_domain = '';
            payload.signed_url_ttl_seconds = 300;
        }
        validateCloudConfigPayload(payload);
        return payload;
    }

    function cloudSizeBytes(form) {
        const unit = cloudSizeUnit(form.elements.max_file_size_unit.value);
        const value = positiveInteger(form.elements.max_file_size_value.value, '单文件上限必须填写正整数');
        return value * unit.bytes;
    }

    function cloudTtlSeconds(form) {
        const unit = cloudTtlUnit(form.elements.signed_url_ttl_unit.value);
        const value = positiveInteger(form.elements.signed_url_ttl_value.value, '短签有效期必须填写正整数');
        return value * unit.seconds;
    }

    function cloudSizeUnit(value) {
        const units = {
            kb: {bytes: 1024},
            mb: {bytes: 1048576},
            gb: {bytes: 1073741824}
        };
        const unit = units[String(value || '')];
        if (!unit) {
            throw new Error('单文件上限单位不支持');
        }
        return unit;
    }

    function cloudTtlUnit(value) {
        const units = {
            second: {seconds: 1},
            minute: {seconds: 60},
            hour: {seconds: 3600}
        };
        const unit = units[String(value || '')];
        if (!unit) {
            throw new Error('短签有效期单位不支持');
        }
        return unit;
    }

    function positiveInteger(value, message) {
        const normalizedValue = String(value ?? '').trim();
        if (!/^[1-9]\d*$/.test(normalizedValue)) {
            throw new Error(message);
        }
        return Number.parseInt(normalizedValue, 10);
    }

    function validateCloudConfigPayload(payload) {
        if (!['local', 'aliyun_oss', 'tencent_cos'].includes(payload.provider)) {
            throw new Error('存储类型不支持');
        }
        assertBinaryFlag(payload.status, '存储状态格式错误');
        assertRange(payload.max_file_size, 1, 10737418240, '单文件上限超出范围');
        assertRange(payload.signed_url_ttl_seconds, 60, 86400, '短签有效期超出范围');
        ['bucket', 'region', 'endpoint', 'access_key', 'path_prefix', 'custom_domain', 'allowed_extensions'].forEach((field) => {
            assertSafeText(payload[field], field === 'allowed_extensions' ? 500 : 255, '云存储配置包含非法字符');
        });
    }

    function remoteApiTokenFormPayload(form) {
        const name = String(form.elements.name.value || '').trim();
        const ipAllowlist = splitTokenList(form.elements.ip_allowlist.value);
        if (name === '') {
            throw new Error('Token 名称不能为空');
        }
        return {
            name,
            expires_at: String(form.elements.expires_at.value || '').trim(),
            ip_allowlist: ipAllowlist
        };
    }

    function renderRemoteApiLogTokenFilter() {
        const select = app.elements.filters.remoteApiLogToken;
        if (!select) {
            return;
        }
        const currentValue = select.value;
        select.innerHTML = '<option value="">全部 Token</option>' + app.state.remoteApiTokens.map((token) => (
            `<option value="${escapeHtml(token.id)}">${escapeHtml(token.name || token.access_key)}</option>`
        )).join('');
        select.value = app.state.remoteApiTokens.some((token) => String(token.id) === currentValue) ? currentValue : '';
        app.state.filters.remoteApiLogs.tokenId = select.value;
    }

    function splitTokenList(value) {
        return String(value || '').split(/[\s,;，；、|]+/u).map((item) => item.trim()).filter(Boolean);
    }

    function filterBySearchAndStatus(rows, filters, fields) {
        return rows.filter((row) => {
            const searchText = fields.map((field) => row[field] || '').join(' ').toLowerCase();
            const matchesSearch = filters.search === '' || searchText.includes(filters.search.toLowerCase());
            const matchesStatus = filters.status === '' || String(row.status) === filters.status;
            return matchesSearch && matchesStatus;
        });
    }

    function filterSelectedCardDevices(rows) {
        return filterBySearchAndStatus(rows, app.state.filters.devices, ['device_name', 'device_hash', 'install_id', 'machine_profile_hash']);
    }

    async function reloadSelectedCardDevices(forceRenderLoading = false) {
        const row = selectedCardRow();
        if (!row) {
            app.view.renderSelectedCardEmpty();
            return;
        }

        const requestSerial = ++selectedCardSyncSerial;
        if (forceRenderLoading) {
            app.view.renderSelectedCard(row, null);
        }
        const data = await app.http.admin('/admin/cards/devices', {app_code: app.state.currentAppCode, card_id: idValue(row.id)});
        if (requestSerial !== selectedCardSyncSerial) {
            return;
        }
        app.state.selectedCardDevices = data.devices || [];
        const latestRow = selectedCardRow();
        if (!latestRow) {
            app.view.renderSelectedCardEmpty();
            return;
        }
        app.view.renderSelectedCard(latestRow, filterSelectedCardDevices(app.state.selectedCardDevices));
    }

    function selectedCardRow() {
        return app.state.cards.find((row) => idValue(row.id) === app.state.selectedCardId) || null;
    }

    async function selectCardsByPreset(status) {
        applyCardStatusPreset(status);
        await loadCards();
        app.state.selectedCardIds.clear();
        app.state.cards.forEach((row) => app.state.selectedCardIds.add(idValue(row.id)));
        await renderFilteredCards();
        const label = cardPresetLabel(status);
        if (app.state.cards.length === 0) {
            app.view.showNotice(`当前没有${label}卡密`, 'info');
            return;
        }
        app.view.showNotice(`已选择 ${app.state.cards.length} 张${label}卡密`);
    }

    function applyCardStatusPreset(status) {
        app.state.filters.cards.status = status;
        if (app.elements.filters.cardStatus) {
            app.elements.filters.cardStatus.value = status;
        }
    }

    function cardPresetLabel(status) {
        if (status === 'expired') {
            return '过期';
        }
        if (status === 'active') {
            return '已激活(未过期)';
        }
        if (status === '0') {
            return '未激活';
        }
        return '目标';
    }

    function onMessageRangeChange() {
        const value = app.elements.filters.messageRange.value;
        app.state.filters.messages.range = value;
        const custom = value === 'custom';
        app.elements.filters.messageStart.hidden = !custom;
        app.elements.filters.messageEnd.hidden = !custom;
        runAsync(loadMessages);
    }

    function onMessageDateChange() {
        app.state.filters.messages.start = app.elements.filters.messageStart.value;
        app.state.filters.messages.end = app.elements.filters.messageEnd.value;
        runAsync(loadMessages);
    }

    function openCardModal() {
        requireCurrentApp();
        openModal('card-modal', '#card-form [name="count"]');
        const form = document.getElementById('card-form');
        updateCardTypeFields(form);
    }

    function openCardImportModal() {
        requireCurrentApp();
        openModal('card-import-modal', '#card-import-form [name="custom_cards"]');
        const form = document.getElementById('card-import-form');
        updateCardTypeFields(form);
        syncCustomCardImport(form);
    }

    function openAppModal() {
        openModal('app-modal', '#app-form [name="name"]');
    }

    function openRemoteApiTokenModal() {
        const modal = openModal('remote-api-token-modal', '#remote-api-token-form [name="name"]');
        const form = modal.querySelector('#remote-api-token-form');
        if (form) {
            form.reset();
        }
    }

    function openTimeModal(node, direction) {
        closeCardActionModal();
        openModal('time-modal');
        const form = document.getElementById('time-form');
        form.elements.card_id.value = node.dataset.id;
        form.elements.card_ids.value = '';
        form.elements.direction.value = direction;
        resetDurationInput(form);
        syncTimeModalText(direction, false, 1);
    }

    function syncTimeModalText(direction, batchMode, cardCount) {
        const title = document.getElementById('time-modal-title');
        const durationLabel = document.getElementById('time-duration-label');
        const submitButton = document.getElementById('time-submit-button');
        const batchSuffix = batchMode ? `（${cardCount} 张）` : '';
        const titleText = {
            add: `卡密加时${batchSuffix}`,
            reduce: `卡密扣时${batchSuffix}`,
            reset: '重置为未激活计时'
        }[direction] || '调整卡密时长';
        title.textContent = titleText;
        durationLabel.textContent = direction === 'reset' ? '目标总时长' : '调整时长';
        submitButton.textContent = direction === 'reset' ? '确认重置' : '确认调整';
    }

    function openModal(modalId, focusSelector) {
        const modal = ensureModal(modalId);
        if (focusSelector) {
            window.setTimeout(() => document.querySelector(focusSelector)?.focus(), 50);
        }
        return modal;
    }

    function closeModal(modalId) {
        const modal = document.getElementById(modalId);
        if (modal) {
            modal.remove();
            if (modalId === 'card-devices-modal') {
                app.state.selectedCardId = '';
                app.state.selectedCardDevices = [];
                selectedCardSyncSerial += 1;
            }
            cacheDynamicModalElements();
        }
    }

    function closeTopModal() {
        const opened = [...document.querySelectorAll('.auth-modal:not([hidden])')].pop();
        if (opened?.id) {
            closeModal(opened.id);
            return;
        }
        if (opened) {
            opened.remove();
        }
    }

    function ensureModal(modalId) {
        const existingModal = document.getElementById(modalId);
        if (existingModal) {
            cacheDynamicModalElements();
            return existingModal;
        }

        const template = document.getElementById(`${modalId}-template`);
        if (!template) {
            throw new Error('弹窗模板不存在');
        }
        app.elements.root.appendChild(template.content.firstElementChild.cloneNode(true));
        cacheDynamicModalElements();
        return document.getElementById(modalId);
    }

    function cacheDynamicModalElements() {
        app.elements.confirmModal = document.getElementById('confirm-modal');
        app.elements.confirmMessage = document.getElementById('confirm-message');
        app.elements.appSecret = document.getElementById('app-secret');
        app.elements.appSecretTitle = document.getElementById('app-secret-title');
        app.elements.appSecretLabel = document.getElementById('app-secret-label');
        app.elements.appSecretBox = app.elements.appSecret?.closest('.secret-box') || null;
        app.elements.appPublicKey = document.getElementById('app-public-key');
        app.elements.copySecretButton = document.getElementById('copy-secret-button');
        app.elements.remoteApiLogDetailTitle = document.getElementById('remote-api-log-detail-title');
        app.elements.remoteApiLogDetailBody = document.getElementById('remote-api-log-detail-body');
        app.elements.sdkDownloadTitle = document.getElementById('sdk-download-title');
        app.elements.sdkDownloadMeta = document.getElementById('sdk-download-meta');
        app.elements.sdkTypeSelect = document.getElementById('sdk-type-select');
        app.elements.appBatchTitle = document.getElementById('app-batch-title');
        app.elements.appBatchMeta = document.getElementById('app-batch-meta');
        app.elements.appBatchList = document.getElementById('app-batch-list');
        app.elements.cardBatchTitle = document.getElementById('card-batch-title');
        app.elements.cardBatchMeta = document.getElementById('card-batch-meta');
        app.elements.cardBatchList = document.getElementById('card-batch-list');
        app.elements.cardRangeTitle = document.getElementById('card-range-title');
        app.elements.cardRangeForm = document.getElementById('card-range-form');
        app.elements.cardRangeDurationField = document.getElementById('card-range-duration-field');
        app.elements.cardRangeDurationLabel = document.getElementById('card-range-duration-label');
        app.elements.variableBatchTitle = document.getElementById('variable-batch-title');
        app.elements.variableBatchMeta = document.getElementById('variable-batch-meta');
        app.elements.variableBatchList = document.getElementById('variable-batch-list');
        app.elements.cardActionTitle = document.getElementById('card-action-title');
        app.elements.cardActionMeta = document.getElementById('card-action-meta');
        app.elements.cardActionList = document.getElementById('card-action-list');
        app.elements.variableModalTitle = document.getElementById('variable-modal-title');
        app.elements.variableForm = document.getElementById('variable-form');
        app.elements.variableAppSearch = document.getElementById('variable-app-search');
        app.elements.variableAppSelected = document.getElementById('variable-app-selected');
        app.elements.variableAppOptions = document.getElementById('variable-app-options');
        app.elements.variableActionTitle = document.getElementById('variable-action-title');
        app.elements.variableActionMeta = document.getElementById('variable-action-meta');
        app.elements.variableActionList = document.getElementById('variable-action-list');
        app.elements.remoteApiTokenForm = document.getElementById('remote-api-token-form');
        app.elements.cloudStorageConfigForm = document.getElementById('cloud-storage-config-form');
        app.elements.cloudConfigState = document.getElementById('cloud-config-state');
        app.elements.cloudUploadForm = document.getElementById('cloud-upload-form');
        app.elements.selectedCardModalTitle = document.getElementById('selected-card-modal-title');
        app.elements.selectedCardEmpty = document.getElementById('selected-card-empty');
        app.elements.selectedCardContent = document.getElementById('selected-card-content');
        app.elements.selectedCardFingerprint = document.getElementById('selected-card-fingerprint');
        app.elements.selectedCardCreated = document.getElementById('selected-card-created');
        app.elements.selectedCardStatus = document.getElementById('selected-card-status');
        app.elements.selectedCardRemaining = document.getElementById('selected-card-remaining');
        app.elements.selectedCardDevicesUsage = document.getElementById('selected-card-devices-usage');
        app.elements.selectedCardOnline = document.getElementById('selected-card-online');
        app.elements.selectedCardIps = document.getElementById('selected-card-ips');
        app.elements.selectedCardUsedAt = document.getElementById('selected-card-used-at');
        app.elements.selectedCardDevices = document.getElementById('selected-card-devices');
        app.elements.filters.deviceSearch = document.getElementById('device-search');
        app.elements.filters.deviceStatus = document.getElementById('device-status-filter');
        app.elements.messageDetailBody = document.getElementById('message-detail-body');
        app.elements.cardsOutput = document.getElementById('cards-output');
        app.elements.customCardImportSummary = document.getElementById('custom-card-import-summary');
    }

    function showSecretModal(secret, publicKey, options = {}) {
        openModal('app-secret-modal');
        const hasSecret = secret !== '';
        if (app.elements.appSecretTitle) {
            app.elements.appSecretTitle.textContent = options.title || '应用信息';
        }
        if (app.elements.appSecretLabel) {
            app.elements.appSecretLabel.textContent = options.secretLabel || '一次性凭据：';
        }
        if (app.elements.appSecretBox) {
            app.elements.appSecretBox.hidden = !hasSecret;
        }
        if (app.elements.copySecretButton) {
            app.elements.copySecretButton.hidden = !hasSecret;
        }
        app.elements.appSecret.textContent = secret;
        if (app.elements.appPublicKey) {
            const publicKeyField = app.elements.appPublicKey.closest('label');
            if (publicKeyField) {
                publicKeyField.hidden = options.hidePublicKey === true;
            }
            app.elements.appPublicKey.value = publicKey || '';
        }
    }

    function showPublicKeyModal(publicKey) {
        showSecretModal('', publicKey, {title: '请求加密公钥'});
    }

    function openAppBatchActions() {
        const appIds = selectedIds('app', '请先选择应用');
        openModal('app-batch-modal');
        app.elements.appBatchTitle.textContent = '批量应用操作';
        app.elements.appBatchMeta.textContent = `当前已选 ${appIds.length} 个应用，批量操作会同时作用到这些应用。`;
        app.elements.appBatchList.innerHTML = appBatchActionItems().map(renderOptionModalButton).join('');
    }

    function appBatchActionItems() {
        return [
            {action: 'batch-enable-apps', text: '批量启用应用', id: 0, app: '', status: 1, tone: 'secondary'},
            {action: 'batch-disable-apps', text: '批量停用应用', id: 0, app: '', status: 0, tone: 'warn'},
            {action: 'batch-delete-apps', text: '批量删除应用', id: 0, app: '', status: 0, tone: 'danger'},
        ];
    }

    function openSdkDownloads() {
        requireCurrentApp();
        openModal('sdk-download-modal');
        app.elements.sdkDownloadTitle.textContent = '下载 SDK';
        app.elements.sdkDownloadMeta.textContent = `${app.state.currentAppName || app.state.currentAppCode} 的接入包会自动写入当前应用信息，下载后可直接调用。`;
        if (app.elements.sdkTypeSelect) {
            app.elements.sdkTypeSelect.value = 'windows';
        }
    }

    function sdkTypeLabel(sdkType) {
        return sdkTypeLabels[String(sdkType || '').toLowerCase()] || 'SDK';
    }

    async function openCardDevices(node) {
        const row = cardRowById(idValue(node.dataset.id));
        if (cardTypeIsRow(row, 'count')) {
            app.view.showNotice('次数卡不绑定设备');
            return;
        }
        app.state.selectedCardId = idValue(row.id);
        app.state.selectedCardDevices = [];
        app.state.filters.devices.search = '';
        app.state.filters.devices.status = '';
        openModal('card-devices-modal');
        bindCardDeviceFilters();
        if (app.elements.selectedCardModalTitle) {
            app.elements.selectedCardModalTitle.textContent = `${row.card_recoverable ? row.card_key : row.card_fingerprint || `#${row.id}`} 设备详情`;
        }
        app.view.renderSelectedCard(row, null);
        await reloadSelectedCardDevices();
    }

    function openSelectedCardActions() {
        const row = selectedCardRow();
        if (!row) {
            throw new Error('请先选中一张卡密');
        }
        openCardActions({dataset: {id: String(row.id)}});
    }

    function openCardBatchActions() {
        const cardIds = selectedIds('card', '请先选择卡密');
        openModal('card-batch-modal');
        app.elements.cardBatchTitle.textContent = '批量卡密操作';
        app.elements.cardBatchMeta.textContent = `当前已选 ${cardIds.length} 张卡密，批量操作会按卡密类型执行。`;
        app.elements.cardBatchList.innerHTML = cardBatchActionItems().map(renderOptionModalButton).join('');
    }

    function openCardActions(node) {
        const row = cardRowById(idValue(node.dataset.id));
        openModal('card-action-modal');
        app.elements.cardActionTitle.textContent = `${row.card_fingerprint || `#${row.id}`} 操作`;
        app.elements.cardActionMeta.textContent = cardActionMeta(row);
        app.elements.cardActionList.innerHTML = cardActionItems(row).map(renderOptionModalButton).join('');
    }

    function cardActionItems(row) {
        const nextStatus = Number(row.status) === 2 ? 0 : 2;
        const items = [
            {action: 'card-status', text: nextStatus === 2 ? '禁用卡密' : '恢复卡密', id: row.id, app: app.state.currentAppCode, status: nextStatus, tone: 'secondary'},
        ];
        if (cardTypeIsRow(row, 'time')) {
            items.push(
                {action: 'card-add-time', text: '卡密加时', id: row.id, app: app.state.currentAppCode, status: 0, tone: 'secondary'},
                {action: 'card-reduce-time', text: '卡密扣时', id: row.id, app: app.state.currentAppCode, status: 0, tone: 'secondary'},
                {action: 'card-reset-time', text: '重置为未激活计时', id: row.id, app: app.state.currentAppCode, status: 0, tone: 'warn'}
            );
        }
        if (cardTypeIsRow(row, 'count')) {
            items.push({action: 'card-reset-uses', text: '重置剩余次数', id: row.id, app: app.state.currentAppCode, status: 0, tone: 'secondary'});
        } else {
            items.push({action: 'card-unbind-all', text: '全部解绑设备', id: row.id, app: app.state.currentAppCode, status: 0, tone: 'warn'});
        }
        items.push({action: 'card-delete', text: '删除卡密', id: row.id, app: app.state.currentAppCode, status: 0, tone: 'danger'});
        return items;
    }

    function cardBatchActionItems() {
        return [
            {action: 'batch-enable-cards', text: '批量启用卡密', id: 0, app: app.state.currentAppCode, status: 0, tone: 'secondary'},
            {action: 'batch-disable-cards', text: '批量禁用卡密', id: 0, app: app.state.currentAppCode, status: 2, tone: 'warn'},
            {action: 'batch-add-time-cards', text: '批量卡密加时', id: 0, app: app.state.currentAppCode, status: 0, tone: 'secondary'},
            {action: 'batch-reduce-time-cards', text: '批量卡密扣时', id: 0, app: app.state.currentAppCode, status: 0, tone: 'warn'},
            {action: 'batch-reset-uses-cards', text: '批量重置次数卡', id: 0, app: app.state.currentAppCode, status: 0, tone: 'secondary'},
            {action: 'batch-enable-card-devices', text: '批量启用绑定设备', id: 0, app: app.state.currentAppCode, status: 1, tone: 'secondary'},
            {action: 'batch-disable-card-devices', text: '批量禁用绑定设备', id: 0, app: app.state.currentAppCode, status: 0, tone: 'warn'},
            {action: 'batch-unbind-card-devices', text: '批量清空绑定设备', id: 0, app: app.state.currentAppCode, status: 0, tone: 'danger'},
            {action: 'open-card-range-operation', text: '按激活日期范围操作', id: 0, app: app.state.currentAppCode, status: 0, tone: 'secondary'},
            {action: 'batch-delete-cards', text: '批量删除卡密', id: 0, app: app.state.currentAppCode, status: 0, tone: 'danger'},
        ];
    }

    function cardActionMeta(row) {
        const onlineText = `在线 ${Number(row.online_count || 0)} 人`;
        if (cardTypeIsRow(row, 'count')) {
            return `不绑定设备 · ${row.remaining_text || '剩余 0 次'} · ${onlineText}`;
        }
        return `设备上限 ${row.max_devices} · 剩余 ${row.remaining_text || '未激活'} · ${onlineText}`;
    }

    function renderOptionModalButton(item) {
        return `<button type="button" class="option-modal-button ${optionToneClass(item.tone)}" data-action="${escapeHtml(item.action)}" data-id="${escapeHtml(item.id || 0)}" data-app="${escapeHtml(item.app || '')}" data-status="${escapeHtml(item.status || 0)}" data-name="${escapeHtml(item.name || '')}" data-enabled="${escapeHtml(item.enabled || 0)}">${escapeHtml(item.text)}</button>`;
    }

    function optionToneClass(tone) {
        return ({
            secondary: 'is-secondary',
            warn: 'is-warn',
            danger: 'is-danger',
        })[tone] || 'is-secondary';
    }

    function closeAppBatchModal() {
        closeModal('app-batch-modal');
    }

    function closeSdkDownloadModal() {
        closeModal('sdk-download-modal');
    }

    function closeCardBatchModal() {
        closeModal('card-batch-modal');
    }

    function closeCardActionModal() {
        closeModal('card-action-modal');
    }

    function bindCardDeviceFilters() {
        const {deviceSearch, deviceStatus} = app.elements.filters;
        if (deviceSearch && deviceSearch.dataset.bound !== '1') {
            deviceSearch.dataset.bound = '1';
            bindFilter(deviceSearch, 'devices', 'search', renderSelectedCardDevices);
        }
        if (deviceStatus && deviceStatus.dataset.bound !== '1') {
            deviceStatus.dataset.bound = '1';
            bindFilter(deviceStatus, 'devices', 'status', renderSelectedCardDevices, 'change');
        }
        if (deviceSearch) {
            deviceSearch.value = app.state.filters.devices.search;
        }
        if (deviceStatus) {
            deviceStatus.value = app.state.filters.devices.status;
        }
    }

    function closeVariableBatchModal() {
        closeModal('variable-batch-modal');
    }

    function closeVariableActionModal() {
        closeModal('variable-action-modal');
    }

    function openBatchCardDurationModal(direction) {
        closeCardBatchModal();
        const cardIds = selectedIds('card', '请先选择卡密');
        openModal('time-modal');
        const form = document.getElementById('time-form');
        form.elements.card_id.value = '';
        form.elements.card_ids.value = cardIds.join(',');
        form.elements.direction.value = direction;
        resetDurationInput(form);
        syncTimeModalText(direction, true, cardIds.length);
    }

    function openCardRangeOperationModal() {
        closeCardBatchModal();
        requireCurrentApp();
        openModal('card-range-modal', '#card-range-form [name="activated_start"]');
        const form = app.elements.cardRangeForm;
        form.reset();
        resetDurationInput(form);
        syncCardRangeDefaultDates(form);
        syncCardRangeOperationForm(form);
    }

    async function copyValue(node) {
        const value = node.dataset.value || node.textContent || '';
        if (value === '') {
            throw new Error('没有可复制的内容');
        }
        await navigator.clipboard.writeText(value);
        app.view.showNotice('内容已复制');
    }

    async function showMessageDetail(node) {
        const message = await app.http.admin('/admin/messages/detail', appCodePayload({message_id: idValue(node.dataset.id)}));
        openModal('message-detail-modal');
        app.elements.messageDetailBody.textContent = JSON.stringify(message.message || {}, null, 2);
    }

    async function readMessage(node) {
        await updateSingleMessage('/admin/messages/read', node, '消息已标记已读');
    }

    async function startHandlingMessage(node) {
        await updateSingleMessage('/admin/messages/handling', node, '消息已标记处理中');
    }

    async function handleMessage(node) {
        await updateSingleMessage('/admin/messages/handle', node, '消息已处理');
    }

    async function archiveMessage(node) {
        await updateSingleMessage('/admin/messages/archive', node, '消息已归档');
    }

    async function deleteMessage(node) {
        if (!await confirmed('确认删除这条消息？')) {
            return;
        }
        await updateSingleMessage('/admin/messages/delete', node, '消息已删除');
    }

    async function actMessage(node) {
        const action = node.dataset.messageAction || '';
        if (!await confirmed(`确认执行 ${messageActionText(action)}？`)) {
            return;
        }
        await app.http.admin('/admin/messages/action', appCodePayload({
            message_id: idValue(node.dataset.id),
            action,
            remark: '后台消息中心手动处置'
        }));
        await loadMessages();
        app.view.showNotice('消息处置已执行');
    }

    async function updateSingleMessage(route, node, notice) {
        await app.http.admin(route, appCodePayload({message_ids: [idValue(node.dataset.id)]}));
        await loadMessages();
        app.view.showNotice(notice);
    }

    async function batchUpdateMessages(route, notice) {
        const messageIds = selectedIds('message', '请先选择消息');
        await app.http.admin(route, appCodePayload({message_ids: messageIds}));
        app.state.selectedMessageIds.clear();
        await loadMessages();
        app.view.showNotice(notice);
    }

    async function clearAppActivityData() {
        requireCurrentApp();
        const appName = currentAppRow()?.name || app.state.currentAppCode;
        if (!await confirmed(`确认清空「${appName}」的活动记录、应用消息和安全上报？该操作不可恢复。`)) {
            return;
        }
        const result = await app.http.admin('/admin/messages/clear-app-activity', appCodePayload());
        app.state.selectedMessageIds.clear();
        await Promise.all([loadMessages(), loadDashboardActivity(), loadApps(), loadOverview()]);
        app.view.showNotice(`已清理消息 ${Number(result.deleted_messages || 0)} 条，活动 ${Number(result.deleted_audit_logs || 0)} 条`);
    }

    function messageActionText(action) {
        return {
            record_only: '只记录',
            manual_review: '人工复核',
            kick_session: '踢下线',
            disable_device: '封禁设备',
            disable_card: '封禁卡密'
        }[String(action)] || action;
    }

    function cardRowById(cardId) {
        const row = app.state.cards.find((item) => idValue(item.id) === idValue(cardId));
        if (!row) {
            throw new Error('卡密不存在');
        }
        return row;
    }

    async function confirmed(message) {
        openModal('confirm-modal');
        app.elements.confirmMessage.textContent = message;
        return new Promise((resolve) => {
            confirmResolver = resolve;
        });
    }

    function resolveConfirm(value) {
        closeModal('confirm-modal');
        if (confirmResolver) {
            confirmResolver(value);
            confirmResolver = null;
        }
    }

    function flagValue(value, defaultValue) {
        return String(value === undefined || value === null || value === '' ? defaultValue : Number(value));
    }

    function clientCryptoOptions() {
        return [
            {value: 'rsa_oaep_aes_256_gcm', label: 'RSA-OAEP + AES-256-GCM'},
            {value: 'rsa_oaep_aes_128_gcm', label: 'RSA-OAEP + AES-128-GCM'},
            {value: 'rsa_pkcs1_aes_256_gcm', label: 'RSA-PKCS1 + AES-256-GCM'}
        ];
    }

    function cardCreatePayload(form) {
        const payload = typedFormData(form, ['count', 'max_devices', 'total_uses', 'card_length', 'unbind_limit']);
        payload.card_type = String(payload.card_type || 'time');
        payload.card_structure = String(payload.card_structure || 'hex');
        payload.duration_seconds = payload.card_type === 'time' ? durationFromForm(form) : 0;
        removeDurationInputFields(payload);
        assertRange(payload.count, 1, 500, '卡密数量必须在 1 到 500 之间');
        validateCardRulePayload(payload);
        assertRange(payload.card_length, 8, 64, '卡密长度必须在 8 到 64 之间');
        if (!['hex', 'alnum'].includes(payload.card_structure)) {
            throw new Error('卡密结构不支持');
        }
        validateCardPrefix(payload.prefix);
        return payload;
    }

    function cardImportPayload(form) {
        const payload = typedFormData(form, ['max_devices', 'total_uses', 'unbind_limit']);
        payload.card_type = String(payload.card_type || 'time');
        payload.duration_seconds = payload.card_type === 'time' ? durationFromForm(form) : 0;
        removeDurationInputFields(payload);
        const customCardImport = parseCustomCardImport(payload.custom_cards || '');
        if (customCardImport.cards.length < 1) {
            throw new Error('请填写要导入的卡密');
        }
        validateCardRulePayload(payload);
        return payload;
    }

    function validateCardRulePayload(payload) {
        if (!['time', 'count', 'permanent'].includes(payload.card_type)) {
            throw new Error('卡密类型不支持');
        }
        if (payload.card_type === 'time') {
            assertRange(payload.duration_seconds, 3600, maxCardDurationSeconds, '有效时长超出范围');
        }
        if (payload.card_type === 'count') {
            assertRange(payload.total_uses, 1, 1000000, '可用次数超出范围');
            payload.max_devices = 0;
            payload.unbind_limit = 0;
            return;
        }
        assertRange(payload.max_devices, 1, 50, '设备上限必须在 1 到 50 之间');
        assertRange(payload.unbind_limit, 0, 1000000, '解绑次数超出范围');
    }

    function parseCustomCardImport(value) {
        const result = inspectCustomCardImport(value);
        assertCustomCardImportResult(result);
        return result;
    }

    function inspectCustomCardImport(value) {
        const text = String(value || '').replace(/^\uFEFF/, '').trim();
        const result = {
            cards: [],
            inputCount: 0,
            duplicateCount: 0,
            invalidCount: 0,
            invalidPreview: '',
            textTooLong: text.length > customCardImportConfig.maxLength,
            blockedCharacter: /[<>"\x00-\x08\x0B\x0C\x0E-\x1F]/.test(text),
            tooMany: false,
            remainingSlots: customCardImportConfig.maxCards
        };
        if (text === '') {
            return result;
        }
        if (result.textTooLong || result.blockedCharacter) {
            return result;
        }

        const tokens = text.split(customCardImportConfig.tokenPattern).filter(Boolean);
        const seenCards = new Set();
        tokens.forEach((token) => {
            if (!customCardImportConfig.cardPattern.test(token)) {
                result.invalidCount += 1;
                result.invalidPreview ||= token;
                return;
            }
            if (seenCards.has(token)) {
                result.duplicateCount += 1;
                return;
            }
            result.cards.push(token);
            seenCards.add(token);
        });
        result.inputCount = tokens.length;
        result.tooMany = result.cards.length > customCardImportConfig.maxCards;
        result.remainingSlots = Math.max(0, customCardImportConfig.maxCards - result.cards.length);
        return result;
    }

    function assertCustomCardImportResult(result) {
        if (result.textTooLong || result.blockedCharacter) {
            throw new Error('自定义卡密格式错误');
        }
        if (result.invalidCount > 0) {
            throw new Error(`自定义卡密格式错误：${result.invalidPreview}`);
        }
        if (result.tooMany) {
            throw new Error('自定义导入最多 500 张');
        }
    }

    function syncCustomCardImport(form) {
        if (!form || !app.elements.customCardImportSummary) {
            return;
        }
        const result = inspectCustomCardImport(form.elements.custom_cards.value);
        app.elements.customCardImportSummary.classList.toggle('is-ready', result.cards.length > 0 && !customCardImportHasError(result));
        app.elements.customCardImportSummary.classList.toggle('is-error', customCardImportHasError(result));
        app.elements.customCardImportSummary.innerHTML = customCardImportSummaryHtml(result);
    }

    function customCardImportHasError(result) {
        return result.textTooLong || result.blockedCharacter || result.invalidCount > 0 || result.tooMany;
    }

    function customCardImportSummaryHtml(result) {
        const parts = [
            `<span class="import-count-main">可导入 ${result.cards.length} / ${customCardImportConfig.maxCards} 张</span>`,
        ];
        if (result.cards.length === 0 && !customCardImportHasError(result)) {
            parts.push('<span>请粘贴要导入的卡密</span>');
            return parts.join('');
        }
        if (result.inputCount > 0) {
            parts.push(`<span>已输入 ${result.inputCount} 项</span>`);
        }
        if (result.duplicateCount > 0) {
            parts.push(`<span>重复 ${result.duplicateCount} 项</span>`);
        }
        if (result.invalidCount > 0) {
            parts.push(`<span class="import-count-error">无效 ${result.invalidCount} 项：${escapeHtml(result.invalidPreview)}</span>`);
        }
        if (result.tooMany) {
            parts.push('<span class="import-count-error">超过 500 张上限</span>');
        } else if (!customCardImportHasError(result)) {
            parts.push(`<span>还可添加 ${result.remainingSlots} 张</span>`);
        }
        if (result.textTooLong || result.blockedCharacter) {
            parts.push('<span class="import-count-error">内容包含不支持字符或长度超限</span>');
        }
        return parts.join('');
    }

    function cardCreateNotice(data) {
        const cardCount = Array.isArray(data.cards) ? data.cards.length : 0;
        if (data.custom_import && Number(data.custom_duplicate_count || 0) > 0) {
            return `已导入 ${cardCount} 张卡密，自动去重 ${Number(data.custom_duplicate_count)} 项`;
        }
        return data.custom_import ? `已导入 ${cardCount} 张卡密` : `已生成 ${cardCount} 张卡密`;
    }

    function appSettingsPayload(form, row) {
        const payload = {
            app_id: idValue(form.elements.app_id.value || row.id),
            name: form.elements.name.value.trim(),
            session_ttl_seconds: numberValue(form.elements.session_ttl_seconds.value),
            heartbeat_enabled: numberValue(form.elements.heartbeat_enabled.value),
            verification_enabled: numberValue(form.elements.verification_enabled.value),
            device_binding_enabled: numberValue(form.elements.device_binding_enabled.value),
            shared_cards_enabled: numberValue(form.elements.shared_cards_enabled.value),
            login_ip_binding_enabled: numberValue(form.elements.login_ip_binding_enabled.value),
            client_crypto_alg: form.elements.client_crypto_alg.value,
            remark: form.elements.remark.value.trim(),
        };
        validateAppSettingsPayload(payload);
        return payload;
    }

    function appApiPayload(form, row) {
        const payload = {
            app_id: idValue(form.elements.app_id.value || row.id),
            api_token: form.elements.api_token.value.trim(),
            api_success_code: numberValue(form.elements.api_success_code.value),
            web_card_query_enabled: numberValue(form.elements.web_card_query_enabled.value),
            unbind_interval_seconds: numberValue(form.elements.unbind_interval_seconds.value),
            unbind_deduct_seconds: numberValue(form.elements.unbind_deduct_seconds.value),
            unbind_deduct_uses: numberValue(form.elements.unbind_deduct_uses.value),
            api_routes: apiRoutePayload(form)
        };
        validateAppApiPayload(payload);
        return payload;
    }

    function apiRoutePayload(form) {
        return [...form.querySelectorAll('[data-api-route]')].map((row) => ({
            route: row.dataset.apiRoute,
            call_id: row.querySelector('[data-api-call-id]').value.trim(),
            enabled: row.querySelector('[data-api-enabled]').value === '1' ? 1 : 0
        }));
    }

    function durationFromForm(form) {
        const unit = durationUnit(form.elements.duration_unit.value);
        const value = durationInputValue(form.elements.duration_value.value);
        assertRange(value, 1, unit.max, '时长数值超出范围');
        return value * unit.seconds;
    }

    function durationInputValue(value) {
        const normalizedValue = String(value ?? '').trim();
        if (!/^[1-9]\d*$/.test(normalizedValue)) {
            throw new Error('时长必须填写正整数');
        }
        return Number.parseInt(normalizedValue, 10);
    }

    function durationUnit(value) {
        const unit = durationUnits[String(value || '')];
        if (!unit) {
            throw new Error('时长单位不支持');
        }
        return unit;
    }

    function removeDurationInputFields(payload) {
        delete payload.duration_value;
        delete payload.duration_unit;
    }

    function cardRangeOperationPayload(form) {
        const operation = form.elements.operation.value;
        const payload = appCodePayload({
            operation,
            activated_start: form.elements.activated_start.value,
            activated_end: form.elements.activated_end.value
        });
        validateCardRangePayload(payload);
        if (cardRangeOperationNeedsDuration(operation)) {
            payload.duration_seconds = durationFromForm(form);
            assertRange(payload.duration_seconds, 3600, maxCardDurationSeconds, '时长超出范围');
        }
        return payload;
    }

    function validateCardRangePayload(payload) {
        if (!cardRangeOperationLabels()[payload.operation]) {
            throw new Error('范围操作类型不支持');
        }
        if (!/^\d{4}-\d{2}-\d{2}$/.test(payload.activated_start) || !/^\d{4}-\d{2}-\d{2}$/.test(payload.activated_end)) {
            throw new Error('请选择完整激活日期范围');
        }
        if (new Date(`${payload.activated_start}T00:00:00`) > new Date(`${payload.activated_end}T23:59:59`)) {
            throw new Error('激活结束日期不能早于开始日期');
        }
    }

    function syncCardRangeDefaultDates(form) {
        const today = new Date();
        const todayText = [
            today.getFullYear(),
            String(today.getMonth() + 1).padStart(2, '0'),
            String(today.getDate()).padStart(2, '0')
        ].join('-');
        form.elements.activated_start.value = todayText;
        form.elements.activated_end.value = todayText;
    }

    function syncCardRangeOperationForm(form) {
        if (!form || !app.elements.cardRangeDurationField || !app.elements.cardRangeDurationLabel) {
            return;
        }
        const operation = form.elements.operation.value;
        const needsDuration = cardRangeOperationNeedsDuration(operation);
        app.elements.cardRangeDurationField.hidden = !needsDuration;
        app.elements.cardRangeDurationLabel.textContent = operation === 'reset_duration' ? '目标时长' : '调整时长';
    }

    function cardRangeOperationNeedsDuration(operation) {
        return ['reset_duration', 'add_duration', 'reduce_duration'].includes(operation);
    }

    function cardRangeOperationLabels() {
        return {
            reset_duration: '重置时长',
            add_duration: '增加时长',
            reduce_duration: '扣减时长',
            enable: '启用卡密',
            disable: '禁用卡密',
            reset_uses: '重置次数卡',
            delete: '删除卡密'
        };
    }

    function cardRangeConfirmText(payload) {
        const label = cardRangeOperationLabels()[payload.operation] || '执行操作';
        const range = `${payload.activated_start} 至 ${payload.activated_end}`;
        if (payload.operation === 'delete') {
            return `确认删除激活日期在 ${range} 内的卡密？`;
        }
        if (payload.operation === 'reset_duration') {
            return `确认把激活日期在 ${range} 内的时长卡重置为未激活计时，并把总时长设为 ${app.view.durationText(payload.duration_seconds)}？设备绑定会保留。`;
        }
        if (payload.operation === 'add_duration' || payload.operation === 'reduce_duration') {
            return `确认对激活日期在 ${range} 内的时长卡${label} ${app.view.durationText(payload.duration_seconds)}？`;
        }
        return `确认对激活日期在 ${range} 内的卡密执行“${label}”？`;
    }

    function cardRangeResultText(response) {
        const affected = Number(response.affected || 0);
        const matched = Number(response.matched || 0);
        return `范围操作完成：匹配 ${matched} 张，处理 ${affected} 张`;
    }

    function resetDurationInput(form) {
        form.querySelectorAll('[data-duration-control]').forEach((control) => {
            control.querySelector('[name="duration_value"]').value = '1';
            control.querySelector('[name="duration_unit"]').value = 'day';
            syncDurationControl(control);
        });
        updateCardTypeFields(form);
    }

    function syncDurationControl(control) {
        if (!control) {
            return;
        }
        const input = control.querySelector('[name="duration_value"]');
        const unit = durationUnit(control.querySelector('[name="duration_unit"]').value);
        input.min = '1';
        input.max = String(unit.max);
        input.placeholder = `1-${unit.max}`;
    }

    function updateCardTypeFields(form) {
        if (!form) {
            return;
        }
        const cardType = String(form.elements.card_type?.value || 'time');
        form.querySelectorAll('[data-card-field="duration"]').forEach((field) => {
            field.hidden = cardType !== 'time';
        });
        form.querySelectorAll('[data-card-field="uses"]').forEach((field) => {
            field.hidden = cardType !== 'count';
        });
        form.querySelectorAll('[data-card-field="devices"], [data-card-field="unbind"]').forEach((field) => {
            field.hidden = cardType === 'count';
        });
        form.querySelectorAll('[data-duration-control]').forEach(syncDurationControl);
    }

    function cardTypeIs(form, type) {
        return String(form?.elements.card_type?.value || 'time') === type;
    }

    function cardTypeIsRow(row, type) {
        return String(row?.card_type || 'time') === type;
    }

    function fillConfigForm(config) {
        const form = app.elements.configForm;
        if (!form) {
            return;
        }
        form.elements.version.value = config?.version || '';
        form.elements.download_url.value = config?.download_url || '';
        form.elements.notice.value = config?.notice || '';
        form.elements.force_update.checked = Number(config?.force_update || 0) === 1;
    }

    function fillAppSettingsForm(row) {
        const form = app.elements.appSettingsForm;
        if (!form || !row) {
            return;
        }
        form.elements.app_id.value = String(row.id || '');
        form.elements.name.value = row.name || '';
        form.elements.session_ttl_seconds.value = String(row.heartbeat_interval || 300);
        form.elements.client_crypto_alg.value = row.client_crypto_alg || 'rsa_oaep_aes_256_gcm';
        form.elements.heartbeat_enabled.value = flagValue(row.heartbeat_enabled, 1);
        form.elements.verification_enabled.value = flagValue(row.verification_enabled, 1);
        form.elements.device_binding_enabled.value = flagValue(row.device_binding_enabled, 1);
        form.elements.shared_cards_enabled.value = flagValue(row.shared_cards_enabled, 0);
        form.elements.login_ip_binding_enabled.value = flagValue(row.login_ip_binding_enabled, 0);
        form.elements.remark.value = row.remark || '';
        if (app.elements.appSettingsMeta) {
            const statusText = Number(row.status) === 1 ? '启用' : '停用';
            app.elements.appSettingsMeta.textContent = `应用编号 ${row.app_code} · 当前状态 ${statusText}`;
        }
    }

    function fillAppApiForm(row) {
        const form = app.elements.appApiForm;
        if (!form || !row) {
            return;
        }
        form.elements.app_id.value = String(row.id || '');
        form.elements.api_token.value = row.api_token || '';
        form.elements.api_success_code.value = String(row.api_success_code ?? 0);
        form.elements.web_card_query_enabled.value = flagValue(row.web_card_query_enabled, 0);
        form.elements.unbind_interval_seconds.value = String(row.unbind_interval_seconds || 0);
        form.elements.unbind_deduct_seconds.value = String(row.unbind_deduct_seconds || 0);
        form.elements.unbind_deduct_uses.value = String(row.unbind_deduct_uses || 0);
        if (app.elements.appApiRoutes) {
            app.elements.appApiRoutes.innerHTML = apiRouteRows(row.api_routes || []);
        }
    }

    function apiRouteRows(routes) {
        return routes.map((route) => `<div class="api-route-item" data-api-route="${escapeHtml(route.route || '')}">
            <div>
                <strong>${escapeHtml(route.name || route.route || '')}</strong>
                <code>${escapeHtml(route.route || '')}</code>
            </div>
            <label><span>开关</span><select name="apiRouteEnabled" data-api-enabled class="layui-input" lay-ignore aria-label="${escapeHtml(route.name || route.route || '')} 接口开关"><option value="1"${Number(route.enabled ?? 1) === 1 ? ' selected' : ''}>开启</option><option value="0"${Number(route.enabled ?? 1) === 0 ? ' selected' : ''}>关闭</option></select></label>
            <label><span>调用 ID</span><input name="apiRouteCallId" data-api-call-id class="layui-input" value="${escapeHtml(route.call_id || '')}" autocomplete="off" maxlength="64" aria-label="${escapeHtml(route.name || route.route || '')} 调用 ID"></label>
        </div>`).join('');
    }

    function renderCurrentAppOperations(row) {
        if (!app.elements.appOperationsMeta || !row) {
            return;
        }
        app.elements.appOperationsMeta.textContent = `${row.name || row.app_code} · ${row.client_crypto_alg || '未设置'}`;
    }

    function renderRemoteVariables() {
        app.view.renderVariables(Array.isArray(app.state.remoteVariables) ? app.state.remoteVariables : []);
        updateSelectionState('variable');
    }

    function openVariableModal(node) {
        const row = node?.dataset?.id ? remoteVariableById(node.dataset.id) : null;
        openModal('variable-modal', row ? '#variable-form [name="value"]' : '#variable-form [name="name"]');
        app.elements.variableModalTitle.textContent = row ? `编辑变量 · ${row.name}` : '添加变量';
        app.elements.variableForm.reset();
        app.elements.variableForm.elements.variable_id.value = row?.id || '';
        app.elements.variableForm.elements.name.value = row?.name || '';
        app.elements.variableForm.elements.value.value = row?.value || '';
        app.elements.variableForm.elements.scope.value = row?.scope || 'public';
        app.elements.variableForm.elements.status.checked = Number(row?.status ?? 1) === 1;
        renderVariableAppOptions(row?.app_ids || []);
        updateVariableScopeFields();
    }

    function editVariable(node) {
        closeVariableActionModal();
        openVariableModal(node);
    }

    async function onSaveVariable(form) {
        const payload = remoteVariableFormPayload(form);
        const route = payload.variable_id ? '/admin/variables/update' : '/admin/variables/create';
        await app.http.admin(route, payload);
        closeModal('variable-modal');
        await loadVariablesPage();
        app.view.showNotice(payload.variable_id ? '远程变量已更新' : '远程变量已添加');
    }

    function openVariableActions(node) {
        const row = remoteVariableById(node.dataset.id);
        openModal('variable-action-modal');
        app.elements.variableActionTitle.textContent = `${row.name} 操作`;
        app.elements.variableActionMeta.textContent = `${variableScopeText(row.scope)} · 当前状态 ${Number(row.status) === 1 ? '启用中' : '已禁用'} · 值长度 ${String(row.value || '').length} 字符`;
        app.elements.variableActionList.innerHTML = variableActionItems(row).map(renderOptionModalButton).join('');
    }

    function variableActionItems(row) {
        const nextStatus = Number(row.status ?? 1) === 1 ? 0 : 1;
        const nextScope = String(row.scope || 'public') === 'public' ? 'private' : 'public';
        return [
            {action: 'edit-variable', text: '编辑变量', id: row.id, tone: 'secondary'},
            {action: 'variable-convert', text: nextScope === 'public' ? '转为公共变量' : '转为私有变量', id: row.id, status: nextScope, tone: 'secondary'},
            {action: 'variable-status', text: nextStatus === 1 ? '启用变量' : '禁用变量', id: row.id, enabled: nextStatus, tone: nextStatus === 1 ? 'secondary' : 'warn'},
            {action: 'variable-delete', text: '删除变量', id: row.id, tone: 'danger'},
        ];
    }

    function openVariableBatchActions() {
        const variableIds = selectedIds('variable', '请先选择变量');
        openModal('variable-batch-modal');
        app.elements.variableBatchTitle.textContent = '批量变量操作';
        app.elements.variableBatchMeta.textContent = `当前已选 ${variableIds.length} 个变量。`;
        app.elements.variableBatchList.innerHTML = variableBatchActionItems().map(renderOptionModalButton).join('');
    }

    function variableBatchActionItems() {
        return [
            {action: 'batch-enable-variables', text: '批量启用变量', tone: 'secondary'},
            {action: 'batch-disable-variables', text: '批量禁用变量', tone: 'warn'},
            {action: 'batch-delete-variables', text: '批量删除变量', tone: 'danger'},
        ];
    }

    async function toggleVariableStatus(node) {
        closeVariableActionModal();
        const row = remoteVariableById(node.dataset.id);
        const enableFlag = numberValue(node.dataset.enabled);
        if (enableFlag === 0 && !await confirmed(`确认禁用变量 ${row.name}？`)) {
            return;
        }
        await app.http.admin('/admin/variables/status', {variable_id: row.id, status: enableFlag});
        await loadVariablesPage();
        app.view.showNotice(enableFlag === 1 ? '远程变量已启用' : '远程变量已禁用');
    }

    async function deleteVariable(node) {
        closeVariableActionModal();
        const row = remoteVariableById(node.dataset.id);
        if (!await confirmed(`确认删除变量 ${row.name}？`)) {
            return;
        }
        await app.http.admin('/admin/variables/delete', {variable_id: row.id});
        await loadVariablesPage();
        app.view.showNotice('远程变量已删除');
    }

    async function convertVariable(node) {
        closeVariableActionModal();
        const row = remoteVariableById(node.dataset.id);
        const nextScope = String(node.dataset.status || 'public');
        if (nextScope === 'private') {
            openVariableModal(node);
            app.elements.variableForm.elements.scope.value = 'private';
            updateVariableScopeFields();
            return;
        }
        if (!await confirmed(`确认将变量 ${row.name} 转为公共变量？`)) {
            return;
        }
        await app.http.admin('/admin/variables/convert', {variable_id: row.id, scope: 'public', app_ids: []});
        await loadVariablesPage();
        app.view.showNotice('远程变量已转为公共变量');
    }

    async function batchEnableVariables() {
        closeVariableBatchModal();
        await applyVariableBatchStatus(1, '启用');
    }

    async function batchDisableVariables() {
        closeVariableBatchModal();
        await applyVariableBatchStatus(0, '禁用');
    }

    async function batchDeleteVariables() {
        closeVariableBatchModal();
        const variableIds = selectedIds('variable', '请先选择变量');
        if (!await confirmed(`确认删除 ${variableIds.length} 个变量？`)) {
            return;
        }
        await app.http.admin('/admin/variables/batch-delete', {variable_ids: variableIds});
        app.state.selectedVariableIds.clear();
        await loadVariablesPage();
        app.view.showNotice('远程变量已批量删除');
    }

    async function applyVariableBatchStatus(enabled, label) {
        const variableIds = selectedIds('variable', '请先选择变量');
        if (enabled === 0 && !await confirmed(`确认${label} ${variableIds.length} 个变量？`)) {
            return;
        }
        await app.http.admin('/admin/variables/batch-status', {variable_ids: variableIds, status: enabled});
        app.state.selectedVariableIds.clear();
        await loadVariablesPage();
        app.view.showNotice(`远程变量已批量${label}`);
    }

    function remoteVariableFormPayload(form) {
        const payload = {
            variable_id: idValue(form.elements.variable_id.value),
            name: String(form.elements.name.value || '').trim(),
            value: String(form.elements.value.value || ''),
            scope: String(form.elements.scope.value || 'public'),
            status: form.elements.status.checked ? 1 : 0,
            app_ids: selectedVariableAppIds()
        };
        return normalizeRemoteVariablePayload(payload);
    }

    function normalizeRemoteVariables(rows) {
        if (!Array.isArray(rows)) {
            return [];
        }
        const normalizedRows = [];
        const invalidNames = [];
        rows.forEach((row) => {
            try {
                normalizedRows.push(normalizeRemoteVariableRow(row));
            } catch (error) {
                invalidNames.push(String(row?.name || row?.id || '未知变量'));
                console.warn(error);
            }
        });
        if (invalidNames.length > 0) {
            app.view.showNotice(`已跳过 ${invalidNames.length} 个格式异常变量：${invalidNames.slice(0, 3).join('、')}`);
        }
        return normalizedRows;
    }

    function normalizeRemoteApiTokens(rows) {
        if (!Array.isArray(rows)) {
            return [];
        }
        return rows.map((row) => ({
            id: idValue(row?.id),
            name: String(row?.name || ''),
            access_key: String(row?.access_key || ''),
            status: Number(row?.status ?? 1) === 0 ? 0 : 1,
            expires_at: String(row?.expires_at || ''),
            ip_allowlist: Array.isArray(row?.ip_allowlist) ? row.ip_allowlist.map(String).filter(Boolean) : [],
            last_used_at: String(row?.last_used_at || ''),
            last_ip: String(row?.last_ip || ''),
            created_by: String(row?.created_by || ''),
            created_at: String(row?.created_at || ''),
            updated_at: String(row?.updated_at || '')
        }));
    }

    function normalizeRemoteApiLogs(rows) {
        if (!Array.isArray(rows)) {
            return [];
        }
        return rows.map((row) => ({
            id: idValue(row?.id),
            token_id: idValue(row?.token_id),
            token_name: String(row?.token_name || ''),
            access_key: String(row?.access_key || ''),
            route: String(row?.route || ''),
            target_app_id: idValue(row?.target_app_id),
            request_hash: String(row?.request_hash || ''),
            app_code: String(row?.app_code || ''),
            app_name: String(row?.app_name || ''),
            status: String(row?.status || ''),
            error_code: String(row?.error_code || ''),
            message: String(row?.message || ''),
            ip: String(row?.ip || ''),
            created_at: String(row?.created_at || '')
        }));
    }

    function normalizeCloudFile(row) {
        return {
            id: idValue(row?.id),
            file_key: String(row?.file_key || ''),
            provider: row?.provider || {value: 'local', label: '服务器本地'},
            original_name: String(row?.original_name || ''),
            mime_type: String(row?.mime_type || ''),
            extension: String(row?.extension || ''),
            size_bytes: numberValue(row?.size_bytes),
            sha256: String(row?.sha256 || ''),
            object_key: String(row?.object_key || ''),
            status: String(row?.status || 'active'),
            remark: String(row?.remark || ''),
            download_count: numberValue(row?.download_count),
            last_download_ip: String(row?.last_download_ip || ''),
            last_download_at: String(row?.last_download_at || ''),
            created_at: String(row?.created_at || ''),
            updated_at: String(row?.updated_at || ''),
            external_download_path: String(row?.external_download_path || '')
        };
    }

    function normalizeRemoteVariablePayload(payload) {
        const normalized = normalizeRemoteVariableRow(payload);
        if (normalized.scope === 'public') {
            normalized.app_ids = [];
        }
        if (normalized.scope === 'private' && normalized.app_ids.length === 0) {
            throw new Error('请选择私有变量授权应用');
        }
        return normalized;
    }

    function normalizeRemoteVariableRow(row) {
        const name = String(row?.name || '').trim();
        if (!/^[A-Za-z0-9_.:-]{1,80}$/.test(name)) {
            throw new Error('远程变量名格式错误');
        }
        const value = normalizeRemoteVariableValue(name, row?.value);
        return {
            id: idValue(row?.id),
            variable_id: idValue(row?.variable_id),
            name,
            value,
            scope: variableScopeValue(row?.scope),
            status: Number(row?.status ?? 1) === 0 ? 0 : 1,
            app_ids: Array.isArray(row?.app_ids) ? row.app_ids.map(idValue).filter(Boolean) : [],
            app_names: Array.isArray(row?.app_names) ? row.app_names.map((name) => String(name || '')).filter(Boolean) : [],
            app_count: numberValue(row?.app_count),
            created_at: String(row?.created_at || ''),
            updated_at: String(row?.updated_at || ''),
        };
    }

    function normalizeRemoteVariableValue(name, value) {
        const text = String(value ?? '');
        if (isRemoteLuaVariableName(name)) {
            assertRemoteLuaStorageValue(text, `远程变量 ${name} 的值格式错误`);
            return text;
        }
        assertSafeTextBlock(text, 4000, `远程变量 ${name} 的值格式错误`);
        return text;
    }

    function isRemoteLuaVariableName(name) {
        return /^ace\.lua\.[A-Za-z0-9_.-]{1,96}$/.test(String(name || ''));
    }

    function assertRemoteLuaStorageValue(value, message) {
        if (String(value || '').length > 60000) {
            throw new Error(message);
        }
        let payload;
        try {
            payload = JSON.parse(String(value || ''));
        } catch (error) {
            throw new Error(message);
        }
        if (!payload || typeof payload !== 'object' || Array.isArray(payload)) {
            throw new Error(message);
        }
        if (payload.format !== 'ace.remoteLua.source.v1') {
            throw new Error(message);
        }
        if (!/^[A-Za-z0-9_-]+$/.test(String(payload.ciphertext || ''))) {
            throw new Error(message);
        }
        if (!/^[A-Fa-f0-9]{64}$/.test(String(payload.sourceSha256 || ''))) {
            throw new Error(message);
        }
    }

    function remoteVariableById(id) {
        const row = app.state.remoteVariables.find((item) => String(item.id) === String(id));
        if (!row) {
            throw new Error('远程变量不存在');
        }
        return row;
    }

    function remoteApiTokenById(id) {
        const token = app.state.remoteApiTokens.find((item) => String(item.id) === String(id));
        if (!token) {
            throw new Error('远程 API Token 不存在');
        }
        return token;
    }

    function remoteApiLogById(id) {
        const log = app.state.remoteApiLogs.find((item) => String(item.id) === String(id));
        if (!log) {
            throw new Error('远程 API 调用日志不存在');
        }
        return log;
    }

    function cloudFileById(id) {
        const row = app.state.cloudFiles.find((item) => String(item.id) === String(id));
        if (!row) {
            throw new Error('云存储文件不存在');
        }
        return row;
    }

    function renderVariableAppOptions(selectedAppIds) {
        selectedVariableAppIdSet = new Set((Array.isArray(selectedAppIds) ? selectedAppIds : []).map(idValue).filter(Boolean));
        if (app.elements.variableAppSearch) {
            app.elements.variableAppSearch.value = '';
        }
        renderVariableAppPicker();
    }

    function renderVariableAppPicker() {
        if (!app.elements.variableAppOptions || !app.elements.variableAppSelected) {
            return;
        }
        const query = String(app.elements.variableAppSearch?.value || '').trim().toLowerCase();
        const filteredApps = app.state.apps.filter((row) => variableAppMatches(row, query));
        app.elements.variableAppSelected.innerHTML = selectedVariableAppTags();
        app.elements.variableAppOptions.innerHTML = filteredApps.length > 0
            ? filteredApps.map(renderVariableAppOption).join('')
            : '<span class="muted-text">没有匹配的应用</span>';
    }

    function renderVariableAppOption(row) {
        const appId = idValue(row.id);
        const selected = selectedVariableAppIdSet.has(appId);
        return `<button type="button" class="variable-app-option${selected ? ' is-selected' : ''}" data-action="variable-app-toggle" data-id="${escapeHtml(appId)}" role="option" aria-selected="${selected ? 'true' : 'false'}"><strong>${escapeHtml(row.name || row.app_code)}</strong><code>${escapeHtml(row.app_code || '')}</code></button>`;
    }

    function selectedVariableAppTags() {
        const selectedIds = selectedVariableAppIds();
        if (selectedIds.length === 0) {
            return '<span class="muted-text">还未选择应用</span>';
        }
        return selectedIds.map((appId) => {
            const row = appById(appId);
            const label = row ? variableAppLabel(row) : appId;
            return `<span class="variable-app-tag"><span>${escapeHtml(label)}</span><button type="button" data-action="variable-app-remove" data-id="${escapeHtml(appId)}" aria-label="移除 ${escapeHtml(label)}">&times;</button></span>`;
        }).join('');
    }

    function variableAppMatches(row, query) {
        if (query === '') {
            return true;
        }
        return variableAppLabel(row).toLowerCase().includes(query) || String(row.app_code || '').toLowerCase().includes(query);
    }

    function variableAppLabel(row) {
        const name = String(row?.name || '').trim();
        const appCode = String(row?.app_code || '').trim();
        return name && appCode && name !== appCode ? `${name} (${appCode})` : (name || appCode);
    }

    function appById(appId) {
        return app.state.apps.find((row) => idValue(row.id) === String(appId));
    }

    function toggleVariableAppSelection(appId) {
        const normalizedId = idValue(appId);
        if (!normalizedId) {
            return;
        }
        if (selectedVariableAppIdSet.has(normalizedId)) {
            selectedVariableAppIdSet.delete(normalizedId);
        } else {
            selectedVariableAppIdSet.add(normalizedId);
        }
        renderVariableAppPicker();
    }

    function removeVariableAppSelection(appId) {
        const normalizedId = idValue(appId);
        if (normalizedId) {
            selectedVariableAppIdSet.delete(normalizedId);
        }
        renderVariableAppPicker();
    }

    function selectedVariableAppIds() {
        return [...selectedVariableAppIdSet].filter((appId) => appById(appId));
    }

    function updateVariableScopeFields() {
        const field = document.getElementById('variable-app-field');
        if (field) {
            const isPrivate = app.elements.variableForm.elements.scope.value === 'private';
            field.hidden = !isPrivate;
            renderVariableAppPicker();
            if (isPrivate) {
                window.setTimeout(() => app.elements.variableAppSearch?.focus(), 30);
            }
        }
    }

    function variableScopeValue(value) {
        const scope = String(value || 'public');
        if (!['public', 'private'].includes(scope)) {
            throw new Error('远程变量作用域错误');
        }
        return scope;
    }

    function variableScopeText(value) {
        return String(value || 'public') === 'private' ? '私有变量' : '公共变量';
    }

    function updateSelectionState(type) {
        const selector = selectionSelector(type);
        const toggleAction = selectionToggleAction(type);
        const batchBar = selectionBatchBar(type);
        const selectedSet = selectionSet(type);
        const inputs = [...document.querySelectorAll(selector)];
        inputs.forEach((input) => {
            input.checked = selectedSet.has(selectionInputId(input, type));
        });
        const selectedVisibleCount = inputs.filter((input) => selectedSet.has(selectionInputId(input, type))).length;
        const toggle = document.querySelector(`[data-action="${toggleAction}"]`);
        if (toggle) {
            toggle.indeterminate = selectedVisibleCount > 0 && selectedVisibleCount < inputs.length;
            toggle.checked = inputs.length > 0 && selectedVisibleCount === inputs.length;
        }
        if (batchBar) {
            batchBar.hidden = selectedSet.size === 0 || !selectionContextVisible(type);
            batchBar.querySelector('strong').textContent = String(selectedSet.size);
        }
    }

    function toggleSelection(type, checked) {
        const selectedSet = selectionSet(type);
        const selector = selectionSelector(type);
        document.querySelectorAll(selector).forEach((input) => {
            const id = selectionInputId(input, type);
            if (checked) {
                selectedSet.add(id);
            } else {
                selectedSet.delete(id);
            }
            input.checked = checked;
        });
        updateSelectionState(type);
    }

    function selectedIds(type, message) {
        pruneSelection(type);
        const ids = [...selectionSet(type)];
        if (ids.length === 0) {
            throw new Error(message);
        }
        return ids;
    }

    function syncSelectionInput(input, type) {
        const selectedSet = selectionSet(type);
        const id = selectionInputId(input, type);
        if (input.checked) {
            selectedSet.add(id);
            return;
        }
        selectedSet.delete(id);
    }

    function selectionSet(type) {
        if (type === 'app') {
            return app.state.selectedAppIds;
        }
        if (type === 'card') {
            return app.state.selectedCardIds;
        }
        if (type === 'message') {
            return app.state.selectedMessageIds;
        }
        return app.state.selectedVariableIds;
    }

    function selectionInputId(input, type) {
        if (type === 'app') {
            return idValue(input.dataset.appId);
        }
        if (type === 'card') {
            return idValue(input.dataset.cardId);
        }
        if (type === 'message') {
            return idValue(input.dataset.messageId);
        }
        return idValue(input.dataset.variableId);
    }

    function pruneSelection(type) {
        const rows = type === 'app'
            ? app.state.apps
            : type === 'card'
                ? app.state.cards
                : type === 'message'
                    ? app.state.messages
                    : app.state.remoteVariables;
        pruneSelectionToRows(type, rows);
    }

    function pruneSelectionToRows(type, rows) {
        const validIds = type === 'variable'
            ? new Set(rows.map((row) => idValue(row.id)))
            : new Set(rows.map((row) => idValue(row.id)));
        const selectedSet = selectionSet(type);
        [...selectedSet].forEach((id) => {
            const normalizedId = type === 'variable' ? String(id) : idValue(id);
            if (!validIds.has(normalizedId)) {
                selectedSet.delete(id);
            }
        });
    }

    function selectionSelector(type) {
        return type === 'app'
            ? 'input[data-app-id]'
            : type === 'card'
                ? 'input[data-card-id]'
                : type === 'message'
                    ? 'input[data-message-id]'
            : 'input[data-variable-id]';
    }

    function selectionToggleAction(type) {
        return type === 'app'
            ? 'toggle-app-selection'
            : type === 'card'
                ? 'toggle-card-selection'
                : type === 'message'
                    ? 'toggle-message-selection'
                    : 'toggle-variable-selection';
    }

    function selectionBatchBar(type) {
        return type === 'app'
            ? app.elements.appBatchBar
            : type === 'card'
                ? app.elements.cardBatchBar
                : type === 'message'
                    ? app.elements.messageBatchBar
                    : app.elements.variableBatchBar;
    }

    function selectionContextVisible(type) {
        if (type === 'app') {
            return app.state.currentView === 'apps';
        }
        if (type === 'card') {
            return app.state.currentView === 'authorization' && app.state.authSection === 'cards';
        }
        if (type === 'message') {
            return app.state.currentView === 'authorization' && app.state.authSection === 'messages';
        }
        return app.state.currentView === 'variables';
    }

    function setTableLoading(target, colspan) {
        target.innerHTML = `<tr><td colspan="${colspan}"><div class="loading-state"><span></span>加载中</div></td></tr>`;
    }

    function appCodePayload(extra) {
        requireCurrentApp();
        return Object.assign({app_code: app.state.currentAppCode}, extra || {});
    }

    function absoluteApiUrl() {
        return new URL(app.state.apiUrl, window.location.href).href;
    }

    function pagingPayload(extra) {
        return Object.assign(appCodePayload({page: 1, limit: 50}), extra || {});
    }

    function messageListPayload() {
        const filters = app.state.filters.messages;
        const payload = pagingPayload({
            limit: 100,
            status: filters.status,
            action: filters.action,
            risk_level: filters.risk,
            event_type: filters.eventType,
            card_fingerprint: filters.cardFingerprint,
            install_id: filters.installId,
            ip: filters.ip
        });
        const range = messageDateRange(filters);
        if (range.start) {
            payload.start = range.start;
        }
        if (range.end) {
            payload.end = range.end;
        }
        return payload;
    }

    function messageDateRange(filters) {
        if (filters.range === 'custom') {
            return {start: filters.start, end: filters.end};
        }
        if (filters.range === 'today') {
            const today = dateInputValue(new Date());
            return {start: today, end: today};
        }
        if (filters.range === '7' || filters.range === '30') {
            const startDate = new Date(Date.now() - (Number(filters.range) - 1) * 86400000);
            return {start: dateInputValue(startDate), end: dateInputValue(new Date())};
        }
        return {start: '', end: ''};
    }

    function dateInputValue(date) {
        const year = date.getFullYear();
        const month = String(date.getMonth() + 1).padStart(2, '0');
        const day = String(date.getDate()).padStart(2, '0');
        return `${year}-${month}-${day}`;
    }

    function actionPayload(node, idName) {
        return {
            [idName]: idName === 'app_code' ? node.dataset.app : idValue(node.dataset.id),
            status: numberValue(node.dataset.status)
        };
    }

    function requireCurrentApp() {
        if (!app.state.currentAppCode) {
            throw new Error('请先从应用管理进入某个应用的授权管理');
        }
        validateAppCode(app.state.currentAppCode);
    }

    function typedFormData(form, numberFields) {
        const payload = formData(form);
        numberFields.forEach((field) => {
            payload[field] = numberValue(payload[field]);
        });
        return payload;
    }

    function formData(form) {
        return Object.fromEntries(new FormData(form).entries());
    }

    function numberValue(value) {
        return Number.parseInt(String(value), 10) || 0;
    }

    function idValue(value) {
        const normalizedValue = String(value ?? '').trim();
        return isPositiveId(normalizedValue) ? normalizedValue : '';
    }

    function csvIdValues(value) {
        return String(value || '')
            .split(',')
            .map((item) => idValue(item))
            .filter(Boolean);
    }

    function validateAppPayload(payload) {
        assertSafeText(payload.name, 80, '应用名称格式错误');
        assertSafeText(payload.remark, 255, '备注格式错误');
        assertClientCryptoAlg(payload.client_crypto_alg);
    }

    function validateAppSettingsPayload(payload) {
        assertPositiveId(payload.app_id, '应用编号无效');
        assertSafeText(payload.name, 80, '应用名称格式错误');
        assertRange(payload.session_ttl_seconds, 300, 315360000, 'Token 过期秒数超出范围');
        assertBinaryFlag(payload.heartbeat_enabled, '心跳续期格式错误');
        assertBinaryFlag(payload.verification_enabled, '卡密验证格式错误');
        assertBinaryFlag(payload.device_binding_enabled, '设备绑定格式错误');
        assertBinaryFlag(payload.shared_cards_enabled, '登录限制格式错误');
        assertBinaryFlag(payload.login_ip_binding_enabled, 'IP 绑定格式错误');
        assertClientCryptoAlg(payload.client_crypto_alg);
        assertSafeText(payload.remark, 255, '备注格式错误');
    }

    function validateAppApiPayload(payload) {
        assertPositiveId(payload.app_id, '应用编号无效');
        if (!/^[A-Za-z0-9_-]{16,64}$/.test(payload.api_token)) {
            throw new Error('请求 Token 格式错误');
        }
        assertRange(payload.api_success_code, 0, 999999, '成功状态码超出范围');
        assertBinaryFlag(payload.web_card_query_enabled, '网页卡密查询格式错误');
        assertRange(payload.unbind_interval_seconds, 0, 315360000, '解绑冷却秒数超出范围');
        assertRange(payload.unbind_deduct_seconds, 0, 315360000, '解绑扣时秒数超出范围');
        assertRange(payload.unbind_deduct_uses, 0, 1000000, '解绑扣次数超出范围');
        const callIds = new Set();
        payload.api_routes.forEach((route) => {
            if (!/^\/[A-Za-z0-9/_-]+$/.test(route.route) || !/^[A-Za-z0-9_.:-]{2,64}$/.test(route.call_id)) {
                throw new Error('接口调用 ID 格式错误');
            }
            if (callIds.has(route.call_id)) {
                throw new Error(`接口调用 ID 重复：${route.call_id}`);
            }
            callIds.add(route.call_id);
        });
    }

    function validateAppCode(appCode) {
        if (!/^[A-Za-z0-9_-]{3,32}$/.test(String(appCode))) {
            throw new Error('应用编号格式错误');
        }
    }

    function validateCardPrefix(prefix) {
        if (String(prefix || '') !== '' && !/^[A-Za-z0-9_-]{1,12}$/.test(String(prefix))) {
            throw new Error('卡密前缀格式错误');
        }
    }

    function assertSafeText(value, maxLength, message) {
        if (String(value || '').length > maxLength || /[<>"\x00-\x1F]/.test(String(value || ''))) {
            throw new Error(message);
        }
    }

    function assertSafeTextBlock(value, maxLength, message) {
        if (String(value || '').length > maxLength || /[<>"\x00-\x08\x0B\x0C\x0E-\x1F]/.test(String(value || ''))) {
            throw new Error(message);
        }
    }

    function assertClientCryptoAlg(value) {
        if (!clientCryptoOptions().some((option) => option.value === value)) {
            throw new Error('客户端加密算法不支持');
        }
    }

    function assertRange(value, min, max, message) {
        if (!Number.isInteger(value) || value < min || value > max) {
            throw new Error(message);
        }
    }

    function assertPositiveId(value, message) {
        if (!isPositiveId(value)) {
            throw new Error(message);
        }
    }

    function isPositiveId(value) {
        const normalizedValue = String(value ?? '').trim();
        const maxIntegerId = '9223372036854775807';
        if (!/^[1-9][0-9]{0,18}$/.test(normalizedValue)) {
            return false;
        }
        return normalizedValue.length < maxIntegerId.length || normalizedValue <= maxIntegerId;
    }

    function assertBinaryFlag(value, message) {
        if (value !== 0 && value !== 1) {
            throw new Error(message);
        }
    }

    function toggleSide() {
        app.elements.root.classList.toggle('side-open');
    }

    function setButtonLoading(node, loading) {
        if (!node || !node.matches('button')) {
            return;
        }
        node.disabled = loading;
        node.classList.toggle('is-loading', loading);
    }

    function runAsync(task, node) {
        setButtonLoading(node, true);
        Promise.resolve().then(task).catch((error) => {
            app.view.showError(error instanceof Error ? error.message : '操作失败');
        }).finally(() => {
            setButtonLoading(node, false);
        });
    }

    function escapeHtml(value) {
        return String(value ?? '').replace(/[&<>"']/g, (char) => ({
            '&': '&amp;',
            '<': '&lt;',
            '>': '&gt;',
            '"': '&quot;',
            "'": '&#39;'
        })[char]);
    }
})(window.NetworkAuthAdmin);
