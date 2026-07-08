(function () {
    'use strict';

    var selector = '[data-mascot-breath]';
    var defaultAmplitude = 2;
    var defaultPeriod = 8800;
    var items = [];
    var running = false;
    var reduceMotion = window.matchMedia && window.matchMedia('(prefers-reduced-motion: reduce)');

    function numericValue(value, fallback) {
        var parsed = Number(value);
        return Number.isFinite(parsed) && parsed > 0 ? parsed : fallback;
    }

    function createItem(element, index) {
        element.dataset.mascotBreathReady = '1';
        element.style.transform = 'translate3d(0, 0, 0)';
        element.style.willChange = 'transform';
        element.style.backfaceVisibility = 'hidden';
        return {
            element: element,
            amplitude: numericValue(element.dataset.mascotBreathAmplitude, defaultAmplitude),
            period: numericValue(element.dataset.mascotBreathPeriod, defaultPeriod),
            phase: numericValue(element.dataset.mascotBreathPhase, index * 420),
            lastTransform: ''
        };
    }

    function collect() {
        var nodes = Array.prototype.slice.call(document.querySelectorAll(selector));
        items = nodes.map(function (element, index) {
            return element.dataset.mascotBreathReady === '1'
                ? findItem(element) || createItem(element, index)
                : createItem(element, index);
        });
        if (items.length > 0 && !running) {
            running = true;
            window.requestAnimationFrame(tick);
        }
    }

    function findItem(element) {
        for (var index = 0; index < items.length; index += 1) {
            if (items[index].element === element) {
                return items[index];
            }
        }
        return null;
    }

    function tick(timestamp) {
        if (reduceMotion && reduceMotion.matches) {
            resetTransforms();
            running = false;
            return;
        }

        for (var index = 0; index < items.length; index += 1) {
            renderItem(items[index], timestamp);
        }
        window.requestAnimationFrame(tick);
    }

    function renderItem(item, timestamp) {
        var progress = ((timestamp + item.phase) % item.period) / item.period;
        var eased = (1 - Math.cos(progress * Math.PI * 2)) / 2;
        var offset = -item.amplitude * eased;
        var nextTransform = 'translate3d(0, ' + offset.toFixed(4) + 'px, 0)';
        if (nextTransform === item.lastTransform) {
            return;
        }
        item.element.style.transform = nextTransform;
        item.lastTransform = nextTransform;
    }

    function resetTransforms() {
        for (var index = 0; index < items.length; index += 1) {
            items[index].element.style.transform = 'translate3d(0, 0, 0)';
            items[index].lastTransform = '';
        }
    }

    function observeDynamicMascots() {
        if (!window.MutationObserver) {
            return;
        }
        var observer = new MutationObserver(function (mutations) {
            for (var index = 0; index < mutations.length; index += 1) {
                if (mutations[index].addedNodes.length > 0) {
                    collect();
                    return;
                }
            }
        });
        observer.observe(document.documentElement, {childList: true, subtree: true});
    }

    function start() {
        collect();
        observeDynamicMascots();
        if (reduceMotion && reduceMotion.addEventListener) {
            reduceMotion.addEventListener('change', collect);
        }
    }

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', start, {once: true});
    } else {
        start();
    }

    window.networkAuthMascotBreathing = {
        refresh: collect
    };
})();
