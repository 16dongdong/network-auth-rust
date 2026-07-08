(function (app) {
    'use strict';

    const viewNames = {
        dashboard: '仪表盘',
        apps: '应用管理',
        settings: '网页配置',
        account: '账号管理',
        variables: '远程变量',
        remoteApi: '远程 API',
        cloudStorage: '云存储',
        authorization: '授权管理'
    };

    const viewSubtitles = {
        dashboard: '平台总览',
        apps: '应用列表',
        settings: '站点与登录页',
        variables: '公共与私有变量',
        remoteApi: '外部自动化管理',
        cloudStorage: '文件管理与下载'
    };

    const authNames = {
        cards: '卡密与设备',
        appConfig: '应用配置',
        integration: '接入文档',
        messages: '消息'
    };

    const imageBasePath = '../../frontend/admin-console/js/img/';
    const brandAvatarImage = 'brand-avatar.webp';
    const toastImages = {
        success: 'save-success.webp',
        error: 'network-error.webp',
        info: 'loading.webp'
    };
    const emptyImages = [
        {keywords: ['卡密', '设备'], image: 'card-management.webp'},
        {keywords: ['设备'], image: 'device-management.webp'},
        {keywords: ['日志', '活动', '消息'], image: 'audit-log.webp'}
    ];
    const mascotScenes = {
        dashboard: {image: 'console-welcome.webp', text: ''},
        apps: {image: 'app-empty.webp', text: ''},
        settings: {image: 'site-settings.webp', text: ''},
        account: {image: 'admin-account.webp', text: ''},
        cards: {image: 'card-management.webp', text: ''},
        appConfig: {image: 'remote-config.webp', text: ''},
        variables: {image: 'remote-config.webp', text: ''},
        remoteApi: {image: 'audit-log.webp', text: ''},
        cloudStorage: {image: 'site-settings.webp', text: ''},
        messages: {image: 'audit-log.webp', text: ''}
    };

    let toastTimer = 0;

    function showNotice(message, type = 'success') {
        clearTimeout(toastTimer);
        if (app.elements.notice.parentElement !== document.body) {
            document.body.appendChild(app.elements.notice);
        }
        app.elements.notice.hidden = false;
        app.elements.notice.className = `auth-toast ${type}`;
        app.elements.notice.innerHTML = renderToast(message, type);
        toastTimer = window.setTimeout(() => {
            app.elements.notice.hidden = true;
        }, 3000);
    }

    function showError(message) {
        showNotice(message, 'error');
    }

    function setActiveView(view) {
        app.state.currentView = view;
        setActiveButtons(view);
        setActivePanel(view);
        setLogoActive(view === 'account');
        updateMascotScene();
        app.elements.pageTitle.textContent = viewNames[view] || view;
        renderHeader();
        closeMobileSide();
    }

    function setAuthSection(section) {
        app.state.authSection = section;
        document.querySelectorAll('[data-auth-view]').forEach((button) => {
            button.classList.toggle('layui-this', button.dataset.authView === section);
        });
        document.querySelectorAll('[data-auth-section]').forEach((panel) => {
            panel.classList.toggle('auth-show', panel.dataset.authSection === section);
        });
        setAppConfigView(app.state.appConfigView);
        updateMascotScene();
        renderHeader();
    }

    function setAppConfigView(view) {
        app.state.appConfigView = view;
        document.querySelectorAll('[data-app-config-view]').forEach((button) => {
            button.classList.toggle('is-active', button.dataset.appConfigView === view);
        });
        document.querySelectorAll('[data-app-config-section]').forEach((panel) => {
            panel.classList.toggle('app-config-pane-show', panel.dataset.appConfigSection === view);
        });
    }

    function setRemoteApiView(view) {
        app.state.remoteApiView = view;
        document.querySelectorAll('[data-remote-api-view]').forEach((button) => {
            button.classList.toggle('layui-this', button.dataset.remoteApiView === view);
        });
        document.querySelectorAll('[data-remote-api-section]').forEach((panel) => {
            panel.classList.toggle('remote-api-pane-show', panel.dataset.remoteApiSection === view);
        });
    }

    function setCloudStorageView() {
        app.state.cloudStorageView = 'files';
        document.querySelectorAll('[data-cloud-storage-section]').forEach((panel) => {
            panel.classList.toggle('cloud-storage-pane-show', panel.dataset.cloudStorageSection === 'files');
        });
    }

    function renderAuthHeader() {
        const appName = app.state.currentAppName || '未选择应用';
        app.elements.authAppName.textContent = appName;
        app.elements.authAppCode.textContent = app.state.currentAppCode ? `(${app.state.currentAppCode})` : '';
        app.elements.activeAppLabel.textContent = app.state.currentAppCode ? `${appName} / ${authNames[app.state.authSection]}` : '未进入应用';
        renderAuthAppTabs();
    }

    function renderAuthAppTabs() {
        if (!app.elements.authAppTabs) {
            return;
        }
        const rows = openedAuthAppRows();
        app.elements.authAppTabs.hidden = rows.length === 0;
        app.elements.authAppTabs.innerHTML = rows.length > 0
            ? `<div class="auth-app-tab-list" role="tablist">${rows.map(authAppTab).join('')}</div>`
            : '';
    }

    function openedAuthAppRows() {
        const appRows = Array.isArray(app.state.apps) ? app.state.apps : [];
        const appRowByCode = new Map(appRows.map((row) => [String(row.app_code || ''), row]));
        return app.state.openedAuthAppCodes
            .map((appCode) => appRowByCode.get(appCode))
            .filter(Boolean);
    }

    function authAppTab(row) {
        const appCode = String(row.app_code || '');
        const isActive = appCode === app.state.currentAppCode;
        const appName = row.name || '未命名应用';
        return `<div class="auth-app-tab ${isActive ? 'is-active' : ''}" role="presentation">
            <button type="button" class="auth-app-tab-main" data-action="switch-auth-app" data-app="${escapeHtml(appCode)}" role="tab" aria-selected="${isActive ? 'true' : 'false'}" title="${escapeHtml(appName)}">
                <strong>${escapeHtml(appName)}</strong>
            </button>
            <button type="button" class="auth-app-tab-close" data-action="close-auth-app" data-app="${escapeHtml(appCode)}" aria-label="关闭 ${escapeHtml(appName)} 标签">&times;</button>
        </div>`;
    }

    function renderHeader() {
        if (app.state.currentView === 'account') {
            renderAccountHeader();
            return;
        }
        if (app.state.currentView === 'authorization') {
            renderAuthHeader();
            return;
        }
        renderMainHeader(app.state.currentView);
    }

    function renderMainHeader(view) {
        app.elements.activeAppLabel.textContent = viewSubtitles[view] || '后台管理';
    }

    function renderAccountHeader() {
        const username = app.state.adminProfile?.username || app.state.adminUsername || '当前管理员';
        app.elements.activeAppLabel.textContent = `${username} / 账号管理`;
    }

    function renderOverview(overview) {
        const values = {
            apps: overview.apps_total,
            cards: overview.cards_total,
            devices: overview.devices_total,
            sessions: overview.sessions_active
        };
        Object.entries(values).forEach(([key, value]) => {
            if (app.elements.stats[key]) {
                app.elements.stats[key].textContent = numberText(value);
            }
        });
        renderMetricGrid(app.elements.overviewCardStatus, [
            ['未激活', overview.card_status?.inactive],
            ['已激活', overview.card_status?.active],
            ['已过期', overview.card_status?.expired],
            ['已禁用', overview.card_status?.disabled]
        ]);
        renderMetricGrid(app.elements.overviewDeviceStatus, [
            ['启用设备', overview.device_status?.enabled],
            ['禁用设备', overview.device_status?.disabled]
        ]);
        renderMetricGrid(app.elements.overviewLoginIpStats, [
            ['登录 IP 数', overview.login_ip_stats?.distinct_count],
            ['单码比例', `${numberText(overview.single_code_ratio?.single_percent)}%`]
        ]);
    }

    function renderOverviewLoading() {
        Object.values(app.elements.stats).forEach((target) => {
            if (target) {
                target.innerHTML = '<span class="skeleton-line skeleton-number"></span>';
            }
        });
        renderMetricGrid(app.elements.overviewCardStatus, []);
        renderMetricGrid(app.elements.overviewDeviceStatus, []);
        renderMetricGrid(app.elements.overviewLoginIpStats, []);
    }

    function renderMetricGrid(target, rows) {
        if (!target) {
            return;
        }
        target.innerHTML = rows.length > 0
            ? rows.map(([label, value]) => `<div class="compact-metric"><span>${escapeHtml(label)}</span><strong>${metricValueText(value)}</strong></div>`).join('')
            : skeletonList(2);
    }

    function metricValueText(value) {
        if (value === undefined || value === null || value === '') {
            return '0';
        }
        const text = String(value);
        return /^-?\d+(\.\d+)?$/.test(text) ? numberText(value) : escapeHtml(text);
    }

    function renderApps(rows) {
        const appCards = rows.map(renderAppCard).join('');
        app.elements.appsGrid.innerHTML = renderAddAppCard()
            + (rows.length > 0 ? appCards : emptyState('layui-icon-app', '暂无应用', ''));
    }

    function renderAppsLoading() {
        app.elements.appsGrid.innerHTML = renderAddAppCard() + skeletonCards(2);
    }

    function renderRecentActivityLoading() {
        app.elements.activitySource.textContent = '正在加载';
        app.elements.recentActivity.innerHTML = skeletonList(4);
    }

    function renderRecentActivity(rows, sourceName) {
        app.elements.activitySource.textContent = sourceName ? `来自 ${sourceName}` : '暂无应用活动';
        app.elements.recentActivity.innerHTML = rows.length > 0
            ? rows.slice(0, 10).map(renderActivityItem).join('')
            : emptyState('layui-icon-log', '暂无最近活动', '');
    }

    function renderCards(rows) {
        renderRows(app.elements.tables.cards, rows, 10, renderCardRow, '暂无卡密', '');
    }

    function renderCardPager(pagination) {
        if (app.elements.cardPageInfo) {
            app.elements.cardPageInfo.textContent = `第 ${numberText(pagination.page)} 页 / 共 ${numberText(pagination.totalPages)} 页 · ${numberText(pagination.total)} 张`;
        }
        if (app.elements.filters.cardPageSize) {
            app.elements.filters.cardPageSize.value = String(pagination.pageSize);
        }
        document.querySelectorAll('[data-action="card-prev-page"]').forEach((button) => {
            button.disabled = pagination.page <= 1;
        });
        document.querySelectorAll('[data-action="card-next-page"]').forEach((button) => {
            button.disabled = pagination.page >= pagination.totalPages;
        });
    }

    function renderVariables(rows) {
        renderRows(app.elements.tables.variables, rows, 8, renderVariableRow, '暂无远程变量', '');
    }

    function renderRemoteApiTokens(rows) {
        renderRows(app.elements.tables.remoteApiTokens, rows, 7, renderRemoteApiTokenRow, '暂无远程 API Token', '');
    }

    function renderRemoteApiLogs(rows) {
        renderRows(app.elements.tables.remoteApiLogs, rows, 5, renderRemoteApiLogRow, '暂无远程 API 调用日志', '');
    }

    function renderCloudSummary(summary) {
        app.state.cloudStorageSummary = summary || null;
        const target = app.elements.cloudStorageSummary;
        if (!target) {
            return;
        }
        const defaultConfig = summary?.default_config || {};
        const token = summary?.download_token || {};
        target.innerHTML = [
            cloudSummaryItem('文件总数', numberText(summary?.file_total), '当前正常文件'),
            cloudSummaryItem('总占用', byteText(summary?.size_total), '当前正常文件'),
            cloudSummaryItem('默认存储', providerLabel(defaultConfig.provider), statusText(defaultConfig.status)),
            cloudSummaryItem('下载 Token', Number(token.status) === 1 ? '启用' : '禁用', token.last_used_at || '未使用')
        ].join('');
    }

    function renderCloudFiles(rows) {
        renderRows(app.elements.tables.cloudFiles, rows, 7, renderCloudFileRow, '暂无云存储文件', '');
    }

    function renderCloudConfigForm(configs, defaultConfig) {
        app.state.cloudStorageConfigs = Array.isArray(configs) ? configs : [];
        const form = app.elements.cloudStorageConfigForm;
        if (!form) {
            return;
        }
        const selectedProvider = form.elements.provider.value || providerValue(defaultConfig?.provider) || 'local';
        const config = app.state.cloudStorageConfigs.find((row) => providerValue(row.provider) === selectedProvider) || {};
        form.elements.provider.value = selectedProvider;
        form.elements.status.value = String(config.status ?? 1);
        fillCloudSizeInput(form, Number(config.max_file_size ?? 104857600));
        fillCloudTtlInput(form, Number(config.signed_url_ttl_seconds ?? 300));
        form.elements.bucket.value = config.bucket || '';
        form.elements.region.value = config.region || '';
        form.elements.endpoint.value = config.endpoint || '';
        form.elements.access_key.value = config.access_key || '';
        form.elements.secret.value = '';
        form.elements.path_prefix.value = config.path_prefix || '';
        form.elements.custom_domain.value = config.custom_domain || '';
        form.elements.allowed_extensions.value = config.allowed_extensions || '';
        form.elements.set_default.checked = Number(config.is_default || 0) === 1;
        syncCloudConfigFields(form, selectedProvider);
        renderCloudConfigState(config, selectedProvider);
    }

    function syncCloudConfigFields(form, selectedProvider) {
        const localProvider = providerValue(selectedProvider) === 'local';
        form.querySelectorAll('[data-cloud-provider-field="remote"]').forEach((field) => {
            field.hidden = localProvider;
            field.querySelectorAll('input, select, textarea').forEach((control) => {
                control.disabled = localProvider;
            });
        });
    }

    function renderCloudConfigState(config, selectedProvider) {
        if (!app.elements.cloudConfigState) {
            return;
        }
        const secretText = providerValue(selectedProvider) === 'local'
            ? '本地存储不需要云厂商 Secret'
            : (config?.secret_saved ? 'Secret 已保存，留空不修改' : 'Secret 未保存');
        app.elements.cloudConfigState.innerHTML = `<span>${escapeHtml(secretText)}</span><span>${escapeHtml(config?.last_test_message || '尚未测试')}</span>`;
    }

    function fillCloudSizeInput(form, bytes) {
        const units = [
            ['gb', 1073741824],
            ['mb', 1048576],
            ['kb', 1024]
        ];
        const [unit, divisor] = units.find(([, value]) => bytes >= value && bytes % value === 0) || ['mb', 1048576];
        form.elements.max_file_size_value.value = String(Math.max(1, Math.round(bytes / divisor)));
        form.elements.max_file_size_unit.value = unit;
        form.elements.max_file_size.value = String(bytes);
    }

    function fillCloudTtlInput(form, seconds) {
        const units = [
            ['hour', 3600],
            ['minute', 60],
            ['second', 1]
        ];
        const [unit, divisor] = units.find(([, value]) => seconds >= value && seconds % value === 0) || ['minute', 60];
        form.elements.signed_url_ttl_value.value = String(Math.max(1, Math.round(seconds / divisor)));
        form.elements.signed_url_ttl_unit.value = unit;
        form.elements.signed_url_ttl_seconds.value = String(seconds);
    }

    function renderCloudDownloadToken(token) {
        app.state.cloudDownloadToken = token || null;
        const tokenText = document.getElementById('cloud-download-token-text');
        const tokenState = document.getElementById('cloud-token-state');
        if (tokenText) {
            tokenText.textContent = token?.token || '';
        }
        if (tokenState) {
            tokenState.innerHTML = [
                cloudSummaryItem('状态', Number(token?.status) === 1 ? '启用' : '禁用', ''),
                cloudSummaryItem('最后使用', token?.last_used_at || '-', token?.last_used_ip || '-')
            ].join('');
        }
    }

    function renderCloudFileDetail(row) {
        const body = document.getElementById('cloud-file-detail-body');
        if (!body) {
            return;
        }
        body.innerHTML = [
            ['文件名', row.original_name || '-'],
            ['文件 Key', row.file_key || '-'],
            ['来源', providerLabel(row.provider)],
            ['Object Key', row.object_key || '-'],
            ['MIME', row.mime_type || '-'],
            ['大小', byteText(row.size_bytes)],
            ['SHA256', row.sha256 || '-'],
            ['下载次数', numberText(row.download_count)],
            ['最后下载 IP', row.last_download_ip || '-'],
            ['最后下载时间', row.last_download_at || '-'],
            ['上传时间', row.created_at || '-']
        ].map(renderDetailItem).join('');
    }

    function renderCloudUploadTarget(summary) {
        const target = document.getElementById('cloud-upload-target');
        if (!target) {
            return;
        }
        const defaultConfig = summary?.default_config || {};
        target.innerHTML = `<span>当前上传目标</span><strong>${escapeHtml(providerLabel(defaultConfig.provider))}</strong>`;
    }

    function renderCloudUploadHash(text) {
        const target = document.getElementById('cloud-upload-hash');
        if (target) {
            target.textContent = text;
        }
    }

    function renderSelectedCardEmpty() {
        if (!app.elements.selectedCardEmpty || !app.elements.selectedCardContent) {
            return;
        }
        app.elements.selectedCardEmpty.hidden = false;
        app.elements.selectedCardContent.hidden = true;
    }

    function renderMessages(rows) {
        renderMessageSummary(rows);
        renderRows(app.elements.tables.messages, rows, 10, renderMessageRow, '暂无消息', '');
    }

    function renderIntegrationDocs(data) {
        if (!app.elements.appIntegrationDocs) {
            return;
        }
        app.elements.appIntegrationDocs.innerHTML = data?.app ? appIntegrationHtml(data) : skeletonList(3);
    }

    function renderIntegrationLoading() {
        if (app.elements.appIntegrationDocs) {
            app.elements.appIntegrationDocs.innerHTML = skeletonList(6);
        }
    }

    function closeMobileSide() {
        app.elements.root.classList.remove('side-open');
    }

    function renderRows(target, rows, colspan, renderer, title, description) {
        target.innerHTML = rows.length > 0
            ? rows.map(renderer).join('')
            : `<tr class="empty-row"><td colspan="${colspan}">${emptyState('layui-icon-face-smile', title, description)}</td></tr>`;
    }

    function renderAddAppCard() {
        return `<button type="button" class="add-app-card" data-action="open-app-modal"><i class="layui-icon layui-icon-add-circle"></i><strong>添加应用</strong></button>`;
    }

    function renderAppCard(row) {
        const metrics = metricsFor(row);
        const nextStatus = Number(row.status) === 1 ? 0 : 1;
        const switchClass = Number(row.status) === 1 ? 'is-on' : '';
        const checked = app.state.selectedAppIds.has(String(row.id)) ? ' checked' : '';
        return `<article class="app-card app-card-clickable" data-open-auth-card data-app="${escapeHtml(row.app_code)}" role="button" tabindex="0" aria-label="${escapeHtml(row.name || row.app_code)} 授权管理">
            <label class="app-check"><input type="checkbox" name="selectedAppIds[]" data-app-id="${escapeHtml(row.id)}" aria-label="选择 ${escapeHtml(row.name || row.app_code)}"${checked}></label>
            <header class="app-card-head">
                <div><span class="status-dot ${Number(row.status) === 1 ? 'on' : 'off'}"></span><h3>${escapeHtml(row.name)}</h3><p>应用编号：${escapeHtml(row.app_code)}</p></div>
                <button type="button" class="status-switch ${switchClass}" data-action="app-status" data-id="${escapeHtml(row.id)}" data-app="${escapeHtml(row.app_code)}" data-status="${nextStatus}" aria-label="切换应用状态"><span></span></button>
            </header>
            <div class="app-metrics"><span>卡密：${numberText(metrics.cards_total)} 张</span><span>在线：${numberText(metrics.sessions_active)}</span><span>设备：${numberText(metrics.devices_total)}</span></div>
            <div class="app-flags">${appFlag(row, 'heartbeat_enabled', '心跳', 1)}${appFlag(row, 'verification_enabled', '验证', 1)}${appFlag(row, 'device_binding_enabled', '设备', 1)}${appFlag(row, 'shared_cards_enabled', '登录', 0)}</div>
            <p class="app-remark">${escapeHtml(row.remark || '无备注')}</p>
        </article>`;
    }

    function renderCardRow(row) {
        return cardMainRow(row);
    }

    function cardMainRow(row) {
        const checked = app.state.selectedCardIds.has(String(row.id)) ? ' checked' : '';
        return `<tr class="card-row">
            <td class="check-cell"><input type="checkbox" name="selectedCardIds[]" data-card-id="${escapeHtml(row.id)}" aria-label="选择卡密 ${escapeHtml(row.card_key || row.id)}"${checked}></td>
            <td>${cardIdentity(row)}</td>
            <td>${cardTypeBadge(row)}</td>
            <td>${cardDurationBadge(row)}</td>
            <td>${cardStatus(row)}</td>
            <td>${remainingBadge(row)}</td>
            <td>${deviceUsageBadge(row)}</td>
            <td>${onlineBadge(row)}</td>
            <td>${lastLoginSummary(row)}</td>
            <td>${cardActionButtons(row)}</td>
        </tr>`;
    }

    function renderMessageRow(row) {
        const checked = app.state.selectedMessageIds.has(String(row.id)) ? ' checked' : '';
        return `<tr>
            <td class="check-cell"><input type="checkbox" name="selectedMessageIds[]" data-message-id="${escapeHtml(row.id)}" aria-label="选择消息 ${escapeHtml(row.id)}"${checked}></td>
            <td>${escapeHtml(row.id)}</td>
            <td>${riskTag(row.risk_level, row.risk_score)}</td>
            <td><div class="table-stacked-cell"><strong>${escapeHtml(eventTypeText(row.event_type))}</strong><small>${escapeHtml(row.event_id || '-')}</small></div></td>
            <td>${messageActionBadge(row.action)}<small class="muted-text">${escapeHtml(row.action_source || '')}</small></td>
            <td>${messageStatusBadge(row.status)}</td>
            <td><button type="button" class="table-text-button" data-action="message-detail" data-id="${escapeHtml(row.id)}">${escapeHtml(truncate(row.title || row.summary, 42))}</button></td>
            <td><div class="table-stacked-cell"><code class="fingerprint-code">${escapeHtml(row.card_fingerprint || '-')}</code><small>${escapeHtml(row.platform || row.ip || '-')}</small></div></td>
            <td title="${escapeHtml(row.created_at)}">${relativeTime(row.created_at)}</td>
            <td>${messageActionButtons(row)}</td>
        </tr>`;
    }

    function renderMessageSummary(rows) {
        if (!app.elements.messageSummary) {
            return;
        }
        const unread = rows.filter((row) => String(row.status || '') === 'unread').length;
        const highRisk = rows.filter((row) => ['high', 'critical'].includes(String(row.risk_level || ''))).length;
        const autoHandled = rows.filter((row) => ['kick_session', 'disable_device', 'disable_card'].includes(String(row.action || ''))).length;
        const pending = rows.filter((row) => ['unread', 'read', 'handling'].includes(String(row.status || ''))).length;
        const items = [
            ['未读', unread],
            ['高危', highRisk],
            ['已自动处置', autoHandled],
            ['待人工处理', pending]
        ];
        app.elements.messageSummary.innerHTML = items.map(([label, value]) => `<div class="message-summary-item"><span>${escapeHtml(label)}</span><strong>${numberText(value)}</strong></div>`).join('');
    }

    function riskTag(riskLevel, riskScore) {
        const level = String(riskLevel || 'low');
        const className = {
            critical: 'danger',
            high: 'danger',
            medium: 'warn',
            low: 'muted'
        }[level] || 'muted';
        return `<span class="status-tag ${className}">${escapeHtml(riskLevelText(level))} ${numberText(riskScore)}</span>`;
    }

    function riskLevelText(level) {
        return {
            critical: '严重',
            high: '高危',
            medium: '中危',
            low: '低危'
        }[level] || level;
    }

    function eventTypeText(type) {
        return {
            debugger_detected: '调试器',
            tracer_detected: '进程跟踪',
            hook_detected: 'Hook',
            instrumentation_detected: '插桩',
            module_tampered: '模块篡改',
            signature_mismatch: '签名异常',
            emulator_detected: '模拟器',
            root_detected: 'Root',
            attestation_failed: '完整性失败',
            policy_violation: '策略违规'
        }[String(type || '')] || String(type || '-');
    }

    function messageActionBadge(action) {
        const normalizedAction = String(action || 'record_only');
        const className = {
            record_only: 'muted',
            manual_review: 'warn',
            kick_session: 'warn',
            disable_device: 'danger',
            disable_card: 'danger'
        }[normalizedAction] || 'muted';
        return `<span class="status-tag ${className}">${escapeHtml(messageActionText(normalizedAction))}</span>`;
    }

    function messageActionText(action) {
        return {
            record_only: '只记录',
            manual_review: '复核',
            kick_session: '踢下线',
            disable_device: '封设备',
            disable_card: '封卡密'
        }[String(action)] || action;
    }

    function messageStatusBadge(status) {
        const normalizedStatus = String(status || 'unread');
        const className = {
            unread: 'warn',
            read: 'muted',
            handling: 'warn',
            handled: 'success',
            archived: 'dark'
        }[normalizedStatus] || 'muted';
        return `<span class="status-tag ${className}">${escapeHtml(messageStatusText(normalizedStatus))}</span>`;
    }

    function messageStatusText(status) {
        return {
            unread: '未读',
            read: '已读',
            handling: '处理中',
            handled: '已处理',
            archived: '已归档'
        }[String(status)] || status;
    }

    function messageActionButtons(row) {
        const id = escapeHtml(row.id);
        const buttons = [
            `<button type="button" class="layui-btn layui-btn-primary layui-btn-xs" data-action="message-detail" data-id="${id}">详情</button>`,
        ];
        if (String(row.status || '') === 'unread') {
            buttons.push(`<button type="button" class="layui-btn layui-btn-primary layui-btn-xs" data-action="message-read" data-id="${id}">已读</button>`);
        }
        if (!['handling', 'handled', 'archived'].includes(String(row.status || ''))) {
            buttons.push(`<button type="button" class="layui-btn layui-btn-primary layui-btn-xs" data-action="message-handling" data-id="${id}">处理中</button>`);
        }
        if (!['handled', 'archived'].includes(String(row.status || ''))) {
            buttons.push(`<button type="button" class="layui-btn layui-btn-primary layui-btn-xs" data-action="message-handle" data-id="${id}">处理</button>`);
        }
        if (['kick_session', 'disable_device', 'disable_card'].includes(String(row.action || ''))) {
            buttons.push(`<button type="button" class="layui-btn layui-btn-danger layui-btn-xs" data-action="message-action" data-id="${id}" data-message-action="${escapeHtml(row.action)}">执行</button>`);
        }
        buttons.push(`<button type="button" class="layui-btn layui-btn-primary layui-btn-xs" data-action="message-archive" data-id="${id}">归档</button>`);
        buttons.push(`<button type="button" class="layui-btn layui-btn-danger layui-btn-xs" data-action="message-delete" data-id="${id}">删除</button>`);
        return `<div class="table-action-group">${buttons.join('')}</div>`;
    }

    function renderVariableRow(row) {
        const variableId = String(row.id || '');
        const checked = app.state.selectedVariableIds.has(variableId) ? ' checked' : '';
        return `<tr>
            <td class="check-cell"><input type="checkbox" name="selectedVariableIds[]" data-variable-id="${escapeHtml(variableId)}" aria-label="选择变量 ${escapeHtml(row.name || '')}"${checked}></td>
            <td><code class="fingerprint-code">${escapeHtml(row.name || '')}</code></td>
            <td>${variableScope(row)}</td>
            <td>${variableApps(row)}</td>
            <td>${variableStatus(row)}</td>
            <td>${variableValueButton(row)}</td>
            <td title="${escapeHtml(row.updated_at || '')}">${relativeTime(row.updated_at)}</td>
            <td><button type="button" class="layui-btn layui-btn-primary layui-btn-xs" data-action="open-variable-actions" data-id="${escapeHtml(variableId)}">操作</button></td>
        </tr>`;
    }

    function renderRemoteApiTokenRow(row) {
        const tokenId = String(row.id || '');
        const nextStatus = Number(row.status) === 1 ? 0 : 1;
        return `<tr>
            <td><strong>${escapeHtml(row.name || '')}</strong><small class="muted-cell">${escapeHtml(row.expires_at || '长期有效')}</small></td>
            <td><code class="fingerprint-code">${escapeHtml(row.access_key || '')}</code></td>
            <td>${remoteApiTokenStatus(row)}</td>
            <td>${remoteApiAllowlist(row)}</td>
            <td><span>${escapeHtml(row.last_used_at || '-')}</span><small class="muted-cell">${escapeHtml(row.last_ip || '-')}</small></td>
            <td>${escapeHtml(row.created_at || '')}</td>
            <td><div class="table-action-group"><button type="button" class="layui-btn layui-btn-primary layui-btn-xs" data-action="remote-api-token-secret" data-id="${escapeHtml(tokenId)}">复制密钥</button><button type="button" class="layui-btn layui-btn-primary layui-btn-xs" data-action="remote-api-token-status" data-id="${escapeHtml(tokenId)}" data-status="${nextStatus}">${nextStatus === 1 ? '启用' : '禁用'}</button><button type="button" class="layui-btn layui-btn-danger layui-btn-xs" data-action="remote-api-token-delete" data-id="${escapeHtml(tokenId)}">删除</button></div></td>
        </tr>`;
    }

    function renderRemoteApiLogRow(row) {
        const logId = String(row.id || '');
        const tokenName = row.token_name || row.access_key || '-';
        return `<tr>
            <td>${escapeHtml(row.created_at || '')}</td>
            <td>${escapeHtml(tokenName)}</td>
            <td>${escapeHtml(remoteApiActionText(row))}</td>
            <td>${remoteApiLogStatus(row)}</td>
            <td>
                <button type="button" class="layui-btn layui-btn-primary layui-btn-xs" data-action="remote-api-log-detail" data-id="${escapeHtml(logId)}">详情</button>
                <button type="button" class="layui-btn layui-btn-danger layui-btn-xs" data-action="remote-api-log-delete" data-id="${escapeHtml(logId)}">删除</button>
            </td>
        </tr>`;
    }

    function renderCloudFileRow(row) {
        const fileId = String(row.id || '');
        return `<tr>
            <td><div class="table-stacked-cell"><strong>${escapeHtml(row.original_name || '')}</strong><small>${escapeHtml(row.mime_type || row.extension || '-')}</small></div></td>
            <td>${escapeHtml(byteText(row.size_bytes))}</td>
            <td>${cloudProviderTag(row.provider)}</td>
            <td><code class="fingerprint-code">${escapeHtml(row.file_key || '')}</code></td>
            <td>${escapeHtml(row.created_at || '')}</td>
            <td>${cloudFileStatus(row.status)}</td>
            <td><div class="table-action-group">
                <button type="button" class="layui-btn layui-btn-primary layui-btn-xs" data-action="copy-cloud-file-link" data-id="${escapeHtml(fileId)}">复制链接</button>
                <button type="button" class="layui-btn layui-btn-primary layui-btn-xs" data-action="cloud-file-detail" data-id="${escapeHtml(fileId)}">详情</button>
                <button type="button" class="layui-btn layui-btn-danger layui-btn-xs" data-action="cloud-file-delete" data-id="${escapeHtml(fileId)}">删除</button>
            </div></td>
        </tr>`;
    }

    function cloudProviderTag(provider) {
        return `<span class="status-tag muted">${escapeHtml(providerLabel(provider))}</span>`;
    }

    function cloudFileStatus(status) {
        return String(status || '') === 'active'
            ? '<span class="status-tag success">正常</span>'
            : '<span class="status-tag danger">已删除</span>';
    }

    function cloudSummaryItem(label, value, hint) {
        return `<div class="cloud-summary-item"><span>${escapeHtml(label)}</span><strong>${escapeHtml(value ?? '-')}</strong><em>${escapeHtml(hint || '')}</em></div>`;
    }

    function providerLabel(provider) {
        const value = providerValue(provider);
        return {
            local: '服务器本地',
            aliyun_oss: '阿里云 OSS',
            tencent_cos: '腾讯云 COS'
        }[value] || '服务器本地';
    }

    function providerValue(provider) {
        if (provider && typeof provider === 'object') {
            return String(provider.value || '');
        }
        return String(provider || '');
    }

    function statusText(status) {
        return Number(status) === 1 ? '启用中' : '已禁用';
    }

    function byteText(value) {
        let size = Number(value || 0);
        const units = ['B', 'KB', 'MB', 'GB', 'TB'];
        let unitIndex = 0;
        while (size >= 1024 && unitIndex < units.length - 1) {
            size /= 1024;
            unitIndex += 1;
        }
        const text = unitIndex === 0 ? String(Math.round(size)) : size.toFixed(size >= 10 ? 1 : 2);
        return `${text} ${units[unitIndex]}`;
    }

    function renderRemoteApiLogDetail(row) {
        if (!app.elements.remoteApiLogDetailTitle || !app.elements.remoteApiLogDetailBody) {
            return;
        }
        app.elements.remoteApiLogDetailTitle.textContent = `调用日志 · ${remoteApiActionText(row)}`;
        app.elements.remoteApiLogDetailBody.innerHTML = remoteApiLogDetailItems(row).map(renderDetailItem).join('');
    }

    function remoteApiLogDetailItems(row) {
        const tokenName = row.token_name || row.access_key || '-';
        const appText = row.app_code ? `${row.app_name || row.app_code} / ${row.app_code}` : '-';
        return [
            ['时间', row.created_at || '-'],
            ['Token', tokenName],
            ['动作', remoteApiActionText(row)],
            ['应用', appText],
            ['结果', String(row.status || '') === 'success' ? '成功' : '失败'],
            ['来源 IP', row.ip || '-'],
            ['错误码', row.error_code || '-'],
            ['消息', row.message || '-'],
            ['AccessKey', row.access_key || '-'],
            ['请求摘要', row.request_hash || '-']
        ];
    }

    function renderDetailItem(item) {
        return `<div class="log-detail-item"><span>${escapeHtml(item[0])}</span><code>${escapeHtml(item[1])}</code></div>`;
    }

    function remoteApiActionText(row) {
        const action = {
            '/remote/variables/list': '查询远程变量',
            '/remote/variables/upsert': '新增或更新远程变量',
            '/remote/variables/status': '启用或禁用远程变量',
            '/remote/variables/delete': '删除远程变量',
            '/remote/variables/convert': '转换变量作用域',
            '/remote/variables/apps/set': '设置私有变量授权应用',
            '/remote/config/get': '读取版本与公告',
            '/remote/config/set': '更新版本与公告',
            '/remote/apps/list': '查询应用列表',
            '/remote/apps/create': '创建应用',
            '/remote/apps/update': '更新应用设置',
            '/remote/apps/status': '启用或停用应用',
            '/remote/apps/delete': '删除应用',
            '/remote/apps/generate-keypair': '重新生成应用密钥',
            '/remote/apps/api/get': '读取接口控制',
            '/remote/apps/api/update': '更新接口控制'
        }[String(row.route || '')];
        if (action) {
            return action;
        }
        return String(row.status || '') === 'success' ? '远程 API 调用' : '远程 API 请求被拒绝';
    }

    function renderActivityItem(row) {
        return `<div class="activity-item"><span class="activity-dot"></span><div><strong>${escapeHtml(row.message || row.action)}</strong><em>${relativeTime(row.created_at)}</em></div></div>`;
    }

    function appIntegrationHtml(data) {
        const appInfo = data.app || {};
        const quickCode = integrationQuickCode();
        return `<div class="integration-workbench">
            <section class="integration-summary">
                <div class="integration-summary-main">
                    <span class="status-tag success">local_key_v1</span>
                    <h3>${escapeHtml(appInfo.name || '当前应用')}</h3>
                    <code>${escapeHtml(appInfo.app_code || '-')}</code>
                </div>
                <div class="integration-summary-actions">
                    <button type="button" class="layui-btn layui-btn-normal layui-btn-sm" data-action="open-sdk-downloads">下载 SDK</button>
                    <button type="button" class="layui-btn layui-btn-primary layui-btn-sm" data-action="copy-integration-params">复制应用参数</button>
                    ${integrationCopyButton('复制接口地址', data.api_url || '')}
                </div>
            </section>
            <section class="integration-steps">
                ${integrationStep(1, '下载 SDK', '选择 Android、Windows、macOS、Linux 或 Python，包内已写入当前应用参数')}
                ${integrationStep(2, '登录卡密', 'SDK 生成本机设备证明')}
                ${integrationStep(3, '读取业务数据', '按需调用 heartbeat、config、variable、logout')}
            </section>
            <section class="integration-code-panel">
                <div class="integration-code-head">
                    <strong>最小调用</strong>
                    ${integrationCopyButton('复制代码', quickCode)}
                </div>
                ${codeBlock(quickCode)}
            </section>
            <details class="integration-details" open>
                <summary>应用参数</summary>
                <div class="integration-param-list">
                    ${integrationParam('接口地址', data.api_url)}
                    ${integrationParam('应用编号', appInfo.app_code)}
                    ${integrationParam('请求 Token', appInfo.api_token)}
                    ${integrationParam('应用版本', appInfo.app_version || '-')}
                    ${integrationParam('成功状态码', appInfo.api_success_code)}
                    ${integrationParam('加密算法', appInfo.client_crypto_alg)}
                    ${integrationParam('Token TTL', `${numberText(appInfo.heartbeat_interval)} 秒`)}
                </div>
            </details>
            <details class="integration-details">
                <summary>客户端接口</summary>
                <div class="integration-table">${integrationRouteRows(data.client_routes || [], appInfo.api_routes || [], appInfo)}</div>
            </details>
            <details class="integration-details">
                <summary>错误码</summary>
                <div class="integration-table compact">${integrationErrorRows(data.error_codes || [])}</div>
            </details>
        </div>`;
    }

    function integrationQuickCode() {
        return [
            'client.login("卡密", "设备安装标识", "设备名称");',
            'client.heartbeat();',
            'client.config();',
            'client.variable("变量名");',
            'client.logout();'
        ].join('\n');
    }

    function integrationStep(index, title, description) {
        return `<div class="integration-step">
            <span>${index}</span>
            <strong>${escapeHtml(title)}</strong>
            <em>${escapeHtml(description)}</em>
        </div>`;
    }

    function integrationParam(label, value) {
        const text = String(value || '-');
        return `<div class="integration-param">
            <span>${escapeHtml(label)}</span>
            <code>${escapeHtml(text)}</code>
            ${text === '-' ? '' : integrationCopyButton('复制', text)}
        </div>`;
    }

    function integrationRouteRows(rows, configuredRoutes, appInfo) {
        const routeConfig = new Map(configuredRoutes.map((row) => [String(row.route || ''), row]));
        return rows.map((row) => `<div class="integration-row">
            <strong>${escapeHtml(row.name || '')}</strong>
            <code>${escapeHtml(row.method || '')} ${escapeHtml(row.route || '')}</code>
            <span>${escapeHtml(routeStateText(row, routeConfig.get(String(row.route || '')), appInfo))}</span>
        </div>`).join('');
    }

    function routeStateText(routeRow, configRow, appInfo) {
        if (String(routeRow.route || '') === '/card/query') {
            return `${Number(appInfo.web_card_query_enabled || 0) === 1 ? '开启' : '关闭'} / 独立开关`;
        }
        if (!configRow) {
            return '未配置';
        }
        return `${Number(configRow.enabled ?? 1) === 1 ? '开启' : '关闭'} / ${configRow.call_id || '-'}`;
    }

    function integrationErrorRows(rows) {
        return rows.map((row) => `<div class="integration-row">
            <strong>${escapeHtml(row.code || '')}</strong>
            <span>${escapeHtml(row.message || '')}</span>
        </div>`).join('');
    }

    function integrationCopyButton(label, value) {
        return `<button type="button" class="layui-btn layui-btn-primary layui-btn-xs" data-action="copy-value" data-value="${escapeHtml(String(value))}">${escapeHtml(label)}</button>`;
    }

    function codeBlock(value) {
        return `<pre class="integration-code"><code>${escapeHtml(value)}</code></pre>`;
    }

    function cardIdentity(row) {
        const cardKey = row.card_recoverable ? String(row.card_key || '') : '旧数据不可恢复';
        const copyAttrs = row.card_recoverable ? ` data-action="copy-value" data-value="${escapeHtml(cardKey)}"` : '';
        return `<div class="card-identity">
            <div class="card-identity-main">
                <button type="button" class="table-text-button direct-value-button"${copyAttrs}>${escapeHtml(cardKey)}</button>
            </div>
            <small>${escapeHtml(row.card_fingerprint || `#${row.id}`)} · ${escapeHtml(row.created_at || '')}</small>
        </div>`;
    }

    function cardActionButtons(row) {
        const devicesButton = isCountCard(row)
            ? ''
            : `<button type="button" class="layui-btn layui-btn-primary layui-btn-xs" data-action="open-card-devices" data-id="${escapeHtml(row.id)}" data-app="${escapeHtml(app.state.currentAppCode)}">设备</button>`;
        return `<div class="table-action-group">
            ${devicesButton}
            <button type="button" class="layui-btn layui-btn-primary layui-btn-xs" data-action="open-card-actions" data-id="${escapeHtml(row.id)}" data-app="${escapeHtml(app.state.currentAppCode)}">操作</button>
        </div>`;
    }

    function deviceUsageBadge(row) {
        if (isCountCard(row)) {
            return '<span class="status-tag muted">不绑定</span>';
        }
        return `<span class="status-tag muted">${numberText(row.device_count)} / ${numberText(row.max_devices)}</span>`;
    }

    function lastLoginSummary(row) {
        const ipHtml = ipList(row.login_ips);
        const usedAt = row.used_at ? escapeHtml(row.used_at) : '还没有首次登录';
        return `<div class="table-stacked-cell">${ipHtml}<small>${usedAt}</small></div>`;
    }

    function variableStatus(row) {
        return Number(row.status ?? 1) === 1
            ? '<span class="status-tag success">启用中</span>'
            : '<span class="status-tag danger">已禁用</span>';
    }

    function variableScope(row) {
        return String(row.scope || 'public') === 'private'
            ? '<span class="status-tag warn">私有</span>'
            : '<span class="status-tag success">公共</span>';
    }

    function variableApps(row) {
        if (String(row.scope || 'public') === 'public') {
            return '<span class="muted-text">全部应用</span>';
        }
        const names = Array.isArray(row.app_names) ? row.app_names : [];
        if (names.length === 0) {
            return '<span class="danger-text">未授权应用</span>';
        }
        const preview = names.slice(0, 2).join(' / ');
        const suffix = names.length > 2 ? ` +${names.length - 2}` : '';
        return `<span title="${escapeHtml(names.join(', '))}">${escapeHtml(preview + suffix)}</span>`;
    }

    function variableValueButton(row) {
        const value = String(row.value ?? '');
        return `<button type="button" class="table-text-button variable-value-button direct-value-block" data-action="edit-variable" data-id="${escapeHtml(row.id || '')}" title="点击编辑变量值">${escapeHtml(value === '' ? '空值' : value)}</button>`;
    }

    function remoteApiTokenStatus(row) {
        return Number(row.status) === 1
            ? '<span class="status-tag success">启用中</span>'
            : '<span class="status-tag danger">已禁用</span>';
    }

    function remoteApiAllowlist(row) {
        const rules = Array.isArray(row.ip_allowlist) ? row.ip_allowlist : [];
        return rules.length === 0 ? '<span class="muted-text">不限制</span>' : escapeHtml(rules.join(', '));
    }

    function remoteApiLogStatus(row) {
        return String(row.status || '') === 'success'
            ? '<span class="status-tag success">成功</span>'
            : '<span class="status-tag danger">失败</span>';
    }

    function renderSelectedCard(row, devices) {
        if (!row) {
            renderSelectedCardEmpty();
            return;
        }
        if (!app.elements.selectedCardEmpty || !app.elements.selectedCardContent || !app.elements.selectedCardFingerprint || !app.elements.selectedCardCreated || !app.elements.selectedCardStatus || !app.elements.selectedCardRemaining || !app.elements.selectedCardDevicesUsage || !app.elements.selectedCardOnline || !app.elements.selectedCardIps || !app.elements.selectedCardUsedAt || !app.elements.selectedCardDevices) {
            return;
        }

        app.elements.selectedCardEmpty.hidden = true;
        app.elements.selectedCardContent.hidden = false;
        app.elements.selectedCardFingerprint.textContent = row.card_recoverable ? row.card_key : '旧数据不可恢复';
        app.elements.selectedCardCreated.textContent = row.created_at || '-';
        app.elements.selectedCardStatus.innerHTML = cardStatus(row);
        app.elements.selectedCardRemaining.textContent = row.remaining_text || '未激活';
        app.elements.selectedCardDevicesUsage.textContent = isCountCard(row) ? '不绑定设备' : `${Number(row.device_count || 0)} / ${Number(row.max_devices || 0)}`;
        app.elements.selectedCardOnline.textContent = Number(row.online_count || 0) > 0
            ? `${Number(row.online_count)} 台正在在线`
            : '当前没有在线设备';
        app.elements.selectedCardIps.innerHTML = ipList(row.login_ips);
        app.elements.selectedCardUsedAt.textContent = row.used_at || '还没有首次登录';
        app.elements.selectedCardDevices.innerHTML = selectedCardDevicesHtml(row, devices);
    }

    function selectedCardDevicesHtml(row, devices) {
        if (isCountCard(row)) {
            return emptyState('layui-icon-auz', '次数卡不绑定设备', '');
        }
        if (devices === null) {
            return '<div class="loading-state"><span></span>正在载入当前卡密的设备</div>';
        }
        if (devices.length === 0) {
            return emptyState('layui-icon-auz', '暂无绑定设备', '');
        }
        return devices.map((device) => selectedCardDeviceItem(row, device)).join('');
    }

    function selectedCardDeviceItem(row, device) {
        const nextStatus = Number(device.status) === 1 ? 0 : 1;
        return `<article class="card-device-item">
            <div class="card-device-main">
                <div class="card-device-head">
                    <strong>${escapeHtml(device.device_name || '未命名设备')}</strong>
                    ${statusTag(device.status)}
                </div>
                <code class="fingerprint-code full-value-code">${escapeHtml(device.device_hash || '')}</code>
                <div class="card-device-meta">
                    <span>设备 ID：${escapeHtml(device.id)}</span>
                    <span>安装标识：${escapeHtml(device.install_id || '-')}</span>
                    <span>环境指纹：${escapeHtml(device.machine_profile_hash || '-')}</span>
                    <span>首次绑定：${escapeHtml(device.first_seen_at || '-')}</span>
                    <span>最近在线：${relativeTime(device.last_seen_at)}</span>
                </div>
            </div>
            <div class="card-device-actions">
                <button type="button" class="layui-btn layui-btn-primary layui-btn-xs" data-action="device-status" data-id="${escapeHtml(device.id)}" data-card-id="${escapeHtml(row.id)}" data-app="${escapeHtml(app.state.currentAppCode)}" data-status="${escapeHtml(nextStatus)}">${nextStatus === 1 ? '启用设备' : '停用设备'}</button>
                <button type="button" class="layui-btn layui-btn-danger layui-btn-xs" data-action="card-unbind-device" data-device-id="${escapeHtml(device.id)}" data-card-id="${escapeHtml(row.id)}" data-app="${escapeHtml(app.state.currentAppCode)}">解绑设备</button>
            </div>
        </article>`;
    }

    function statusTag(status) {
        return Number(status) === 1
            ? '<span class="status-tag success">启用</span>'
            : '<span class="status-tag danger">停用</span>';
    }

    function appFlag(row, field, label, enabledValue) {
        const enabled = Number(row[field] ?? enabledValue) === 1;
        return `<span class="app-flag ${enabled ? 'is-enabled' : 'is-disabled'}">${escapeHtml(label)}${enabled ? '开' : '关'}</span>`;
    }

    function cardStatus(row) {
        const value = Number(row.status);
        if (value === 2) {
            return '<span class="status-tag danger">已禁用</span>';
        }
        if (isExpired(row)) {
            return '<span class="status-tag dark">已过期</span>';
        }
        if (value === 1) {
            return '<span class="status-tag success">已激活</span>';
        }
        return '<span class="status-tag muted">未激活</span>';
    }

    function cardTypeBadge(row) {
        return `<span class="status-tag muted">${escapeHtml(cardTypeText(row.card_type))}</span>`;
    }

    function cardTypeText(type) {
        return {
            time: '时长卡',
            count: '次数卡',
            permanent: '永久卡'
        }[String(type || 'time')] || String(type || '未知');
    }

    function cardDurationBadge(row) {
        const category = String(row.duration_category || '');
        const className = category === 'custom' ? 'warn' : 'muted';
        return `<span class="status-tag ${className}">${escapeHtml(row.duration_text || cardDurationText(row))}</span>`;
    }

    function cardDurationText(row) {
        if (String(row.card_type || 'time') === 'permanent') {
            return '永久';
        }
        if (isCountCard(row)) {
            return `${numberText(row.total_uses)} 次`;
        }
        return durationText(row.duration_seconds);
    }

    function durationText(seconds) {
        const value = Number(seconds || 0);
        if (value <= 0) {
            return '未设置';
        }
        const days = Math.floor(value / 86400);
        const hours = Math.floor((value % 86400) / 3600);
        const minutes = Math.floor((value % 3600) / 60);
        if (days > 0 && hours === 0 && minutes === 0) {
            return `${days}天`;
        }
        if (days > 0) {
            return `${days}天${hours}小时`;
        }
        if (hours > 0) {
            return minutes > 0 ? `${hours}小时${minutes}分钟` : `${hours}小时`;
        }
        return `${Math.max(1, minutes)}分钟`;
    }

    function remainingBadge(row) {
        if (isCountCard(row)) {
            return `<span class="success-text">${escapeHtml(row.remaining_text || '剩余 0 次')}</span>`;
        }
        if (Number(row.status) === 0 || row.remaining_seconds === null) {
            return '<span class="muted-text">未激活</span>';
        }
        if (isExpired(row)) {
            return '<span class="danger-text">已过期</span>';
        }
        return `<span class="success-text">${escapeHtml(row.remaining_text || remainingText(row.remaining_seconds))}</span>`;
    }

    function onlineBadge(row) {
        const count = Number(row.online_count || 0);
        return count > 0
            ? `<span class="status-tag success">${numberText(count)} 人</span>`
            : '<span class="muted-text">0</span>';
    }

    function ipList(value) {
        const ips = Array.isArray(value) ? value : String(value || '').split(',');
        const normalized = ips.map((ip) => String(ip).trim()).filter(Boolean);
        if (normalized.length === 0) {
            return '<span class="muted-text">-</span>';
        }
        const preview = normalized.slice(0, 2).join(' / ');
        const suffix = normalized.length > 2 ? ` +${normalized.length - 2}` : '';
        return `<code class="fingerprint-code" title="${escapeHtml(normalized.join(', '))}">${escapeHtml(preview + suffix)}</code>`;
    }

    function isExpired(row) {
        return Number(row.status) === 1 && Number(row.remaining_seconds || 0) <= 0;
    }

    function isCountCard(row) {
        return String(row?.card_type || 'time') === 'count';
    }

    function metricsFor(row) {
        return app.state.appMetrics.get(String(row.app_code)) || {};
    }

    function setActiveButtons(view) {
        document.querySelectorAll('[data-view]').forEach((node) => {
            const item = node.matches('li') ? node : node.closest('.layui-nav-item');
            if (item) {
                item.classList.toggle('layui-this', node.dataset.view === view);
            }
        });
    }

    function setLogoActive(active) {
        app.elements.logoButton?.classList.toggle('is-active', active);
    }

    function setActivePanel(view) {
        document.querySelectorAll('[data-panel]').forEach((panel) => {
            panel.classList.toggle('layui-show', panel.dataset.panel === view);
        });
    }

    function emptyState(icon, title, description) {
        const image = emptyImage(title, description, icon);
        const descriptionHtml = description ? `<p class="mascot-text">${escapeHtml(description)}</p>` : '';
        return `<div class="empty-state anime-empty">
            <img class="mascot-img empty-illustration" src="${assetImage(image)}" alt="" loading="lazy" data-mascot-breath data-mascot-breath-amplitude="2" data-mascot-breath-period="8800">
            <i class="layui-icon ${icon}"></i>
            <strong class="empty-title">${escapeHtml(title)}</strong>
            ${descriptionHtml}
        </div>`;
    }

    function emptyImage(title, description, icon) {
        const matched = emptyImages.find((item) => item.keywords.some((keyword) => title.includes(keyword)))
            || emptyImages.find((item) => item.keywords.some((keyword) => `${description} ${icon}`.includes(keyword)));
        return matched ? matched.image : 'app-empty.webp';
    }

    function renderToast(message, type) {
        const image = toastImages[type] || toastImages.info;
        return `<img class="toast-mascot" src="${assetImage(image)}" alt="" aria-hidden="true"><span class="toast-message">${escapeHtml(message)}</span>`;
    }

    function skeletonCards(count) {
        return Array.from({length: count}, () => '<div class="skeleton-card"><span></span><strong></strong><em></em></div>').join('');
    }

    function skeletonList(count) {
        return Array.from({length: count}, () => '<div class="skeleton-row"><span></span><strong></strong></div>').join('');
    }

    function relativeTime(value) {
        const timestamp = Date.parse(String(value || '').replace(' ', 'T'));
        if (!timestamp) {
            return '-';
        }
        const seconds = Math.max(0, Math.floor((Date.now() - timestamp) / 1000));
        if (seconds < 60) {
            return '刚刚';
        }
        if (seconds < 3600) {
            return `${Math.floor(seconds / 60)}分钟前`;
        }
        if (seconds < 86400) {
            return `${Math.floor(seconds / 3600)}小时前`;
        }
        return `${Math.floor(seconds / 86400)}天前`;
    }

    function remainingText(seconds) {
        const value = Number(seconds || 0);
        const days = Math.floor(value / 86400);
        const hours = Math.floor((value % 86400) / 3600);
        return days > 0 ? `${days}天${hours}小时` : `${hours}小时`;
    }

    function truncate(value, maxLength) {
        const text = String(value || '');
        return text.length > maxLength ? `${text.slice(0, maxLength)}...` : text;
    }

    function numberText(value) {
        return String(Number(value || 0));
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

    function applySiteBranding(settings) {
        if (!settings) {
            return;
        }

        app.state.siteSettings = settings;
        const hostname = settings.hostname || '授权管理系统';
        const subtitle = settings.site_subtitle || '授权管理平台';
        if (app.elements.siteBrandName) {
            app.elements.siteBrandName.textContent = hostname;
        }
        if (app.elements.siteBrandSubtitle) {
            app.elements.siteBrandSubtitle.textContent = subtitle;
        }
        if (app.elements.documentTitle) {
            app.elements.documentTitle.textContent = hostname;
        }

        const logoMark = document.querySelector('.auth-logo-mark img.auth-logo-avatar');
        if (logoMark) {
            logoMark.src = settings.logo_url || assetImage(brandAvatarImage);
        }
        if (app.elements.adminAccountAvatar) {
            app.elements.adminAccountAvatar.src = settings.logo_url || assetImage(brandAvatarImage);
        }

        if (app.elements.sideMascotText) {
            const currentScene = resolvedMascotScene();
            app.elements.sideMascotText.textContent = webSettings(settings).side_mascot_text || currentScene.text;
        }
        updateMascotScene();
    }

    function renderAdminProfile(profile) {
        app.state.adminProfile = profile || null;
        const username = profile?.username || app.state.adminUsername || '';
        if (app.elements.adminProfileUsername) {
            app.elements.adminProfileUsername.value = username;
        }
        if (app.elements.adminProfileCurrentUsername) {
            app.elements.adminProfileCurrentUsername.textContent = username || '-';
        }
        if (app.elements.adminProfileRememberStatus) {
            app.elements.adminProfileRememberStatus.textContent = profile?.remember_login_active ? '已启用' : '未启用';
        }
        if (app.elements.adminProfileRememberExpires) {
            app.elements.adminProfileRememberExpires.textContent = profile?.remember_login_active && profile?.remember_login_expires_at
                ? `到期：${profile.remember_login_expires_at}`
                : '当前设备未保存记住登录';
        }
        if (app.elements.adminProfileSessionExpires) {
            app.elements.adminProfileSessionExpires.textContent = profile?.session_expires_at || app.state.adminSessionExpiresAt || '-';
        }
        if (app.elements.adminProfileUpdatedAt) {
            app.elements.adminProfileUpdatedAt.textContent = profile?.updated_at ? `更新于 ${relativeTime(profile.updated_at)}` : '-';
        }
        if (app.elements.adminProfileCreatedAt) {
            app.elements.adminProfileCreatedAt.textContent = profile?.created_at ? `创建于 ${profile.created_at}` : '创建时间未知';
        }
        if (app.state.currentView === 'account') {
            renderAccountHeader();
        }
    }

    function fillSiteSettingsForm(settings) {
        const form = app.elements.siteSettingsForm;
        if (!form || !settings) {
            return;
        }

        form.hostname.value = settings.hostname || '';
        form.site_subtitle.value = settings.site_subtitle || '';
        form.logo_url.value = settings.logo_url || '';
        form.contact.value = settings.contact || '';
        form.footer_text.value = settings.footer_text || '';
        form.announcement.value = settings.announcement || '';
        const web = webSettings(settings);
        form.login_title.value = web.login_title || '';
        form.login_subtitle.value = web.login_subtitle || '';
        form.login_badge.value = web.login_badge || '';
        form.login_notice.value = web.login_notice || '';
        form.side_mascot_text.value = web.side_mascot_text || '';
    }

    function webSettings(settings) {
        const custom = settings?.custom_json || {};
        return custom && typeof custom.web === 'object' && !Array.isArray(custom.web) ? custom.web : {};
    }

    function assetImage(filename) {
        return imageBasePath + encodeURIComponent(filename);
    }

    function resolvedMascotScene() {
        if (app.state.currentView === 'authorization') {
            return mascotScenes[app.state.authSection] || mascotScenes.cards;
        }
        return mascotScenes[app.state.currentView] || mascotScenes.dashboard;
    }

    function updateMascotScene() {
        const scene = resolvedMascotScene();
        if (app.elements.sideMascotImage) {
            setImageSource(app.elements.sideMascotImage, assetImage(scene.image));
        }
        if (app.elements.sideMascotText) {
            const customText = webSettings(app.state.siteSettings).side_mascot_text || '';
            app.elements.sideMascotText.textContent = customText || scene.text;
        }
    }

    function setImageSource(image, source) {
        if (image.getAttribute('src') === source) {
            return;
        }
        image.src = source;
    }

    app.view = {
        applySiteBranding,
        closeMobileSide,
        durationText,
        fillSiteSettingsForm,
        renderAdminProfile,
        renderApps,
        renderAppsLoading,
        renderMessages,
        renderAuthHeader,
        renderHeader,
        renderCards,
        renderCardPager,
        renderIntegrationDocs,
        renderIntegrationLoading,
        renderVariables,
        renderRemoteApiTokens,
        renderRemoteApiLogs,
        renderRemoteApiLogDetail,
        renderCloudSummary,
        renderCloudFiles,
        renderCloudConfigForm,
        renderCloudDownloadToken,
        renderCloudFileDetail,
        renderCloudUploadTarget,
        renderCloudUploadHash,
        remoteApiActionText,
        renderSelectedCard,
        renderSelectedCardEmpty,
        renderOverview,
        renderOverviewLoading,
        renderRecentActivity,
        renderRecentActivityLoading,
        setActiveView,
        setAppConfigView,
        setRemoteApiView,
        setCloudStorageView,
        setAuthSection,
        showError,
        showNotice
    };
})(window.NetworkAuthAdmin);
