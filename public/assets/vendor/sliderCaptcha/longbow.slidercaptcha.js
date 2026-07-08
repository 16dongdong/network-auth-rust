(function () {
    'use strict';

    var extend = function () {
        var length = arguments.length;
        var target = arguments[0] || {};
        if (typeof target != "object" && typeof target != "function") {
            target = {};
        }
        if (length == 1) {
            target = this;
            i--;
        }
        for (var i = 1; i < length; i++) {
            var source = arguments[i];
            for (var key in source) {
                // 使用for in会遍历数组所有的可枚举属性，包括原型。
                if (Object.prototype.hasOwnProperty.call(source, key)) {
                    target[key] = source[key];
                }
            }
        }
        return target;
    }

    var isFunction = function isFunction(obj) {
        return typeof obj === "function" && typeof obj.nodeType !== "number";
    };

    var SliderCaptcha = function (element, options) {
        this.$element = element;
        this.options = extend({}, SliderCaptcha.DEFAULTS, options);
        this.$element.style.position = 'relative';
        this.$element.style.width = this.options.width + 'px';
        this.$element.style.margin = '0 auto';
        this.init();
    };

    SliderCaptcha.VERSION = '1.0';
    SliderCaptcha.Author = 'argo@163.com';
    SliderCaptcha.DEFAULTS = {
        width: 280,     // canvas宽度
        height: 155,    // canvas高度
        PI: Math.PI,
        sliderL: 42,    // 滑块边长
        sliderR: 9,     // 滑块半径
        offset: 8,      // 容错偏差
        loadingText: '正在加载中...',
        failedText: '再试一次',
        barText: '向右滑动填充拼图',
        repeatIcon: '',
        maxLoadCount: 3,
        imageUrl: null,
        puzzleX: null,
        puzzleY: null,
        localImages: function () {
            return 'images/Pic' + Math.round(Math.random() * 4) + '.jpg';
        },
        verify: function (arr, url) {
            var ret = false;
            $.ajax({
                url: url,
                data: {
                    "datas": JSON.stringify(arr),
                },
                dataType: "json",
                type: "post",
                async: false,
                success: function (result) {
                    ret = JSON.stringify(result);
                }
            });
            return ret;
        },
        remoteUrl: null
    };

    function Plugin(option) {
        var $this = document.getElementById(option.id);
        var options = typeof option === 'object' && option;
        return new SliderCaptcha($this, options);
    }

    window.sliderCaptcha = Plugin;
    window.sliderCaptcha.Constructor = SliderCaptcha;

    var _proto = SliderCaptcha.prototype;
    _proto.init = function () {
        this.initDOM();
        this.initImg();
        this.bindEvents();
    };

    _proto.initDOM = function () {
        var createElement = function (tagName, className) {
            var elment = document.createElement(tagName);
            elment.className = className;
            return elment;
        };

        var createCanvas = function (width, height) {
            var canvas = document.createElement('canvas');
            canvas.width = width;
            canvas.height = height;
            return canvas;
        };

        var canvas = createCanvas(this.options.width - 2, this.options.height); // 画布
        var block = canvas.cloneNode(true); // 滑块
        var sliderContainer = createElement('div', 'sliderContainer');
        var refreshIcon = createElement('button', 'refreshIcon ' + this.options.repeatIcon);
        var sliderMask = createElement('div', 'sliderMask');
        var sliderbg = createElement('div', 'sliderbg');
        var slider = createElement('div', 'slider');
        var sliderIcon = createElement('span', 'sliderIcon');
        var text = createElement('span', 'sliderText');

        block.className = 'block';
        text.innerHTML = this.options.barText;
        refreshIcon.type = 'button';
        refreshIcon.setAttribute('aria-label', '刷新拼图验证');
        slider.setAttribute('role', 'slider');
        slider.setAttribute('tabindex', '0');
        slider.setAttribute('aria-label', '拖动或按方向键移动拼图滑块');
        slider.setAttribute('aria-valuemin', '0');
        sliderIcon.textContent = '>';

        var el = this.$element;
        el.appendChild(canvas);
        el.appendChild(refreshIcon);
        el.appendChild(block);
        slider.appendChild(sliderIcon);
        sliderMask.appendChild(slider);
        sliderContainer.appendChild(sliderbg);
        sliderContainer.appendChild(sliderMask);
        sliderContainer.appendChild(text);
        el.appendChild(sliderContainer);

        var _canvas = {
            canvas: canvas,
            block: block,
            sliderContainer: sliderContainer,
            refreshIcon: refreshIcon,
            slider: slider,
            sliderMask: sliderMask,
            sliderIcon: sliderIcon,
            text: text,
            canvasCtx: canvas.getContext('2d'),
            blockCtx: block.getContext('2d')
        };

        if (isFunction(Object.assign)) {
            Object.assign(this, _canvas);
        }
        else {
            extend(this, _canvas);
        }
    };

    _proto.initImg = function () {
        var that = this;
        var isIE = window.navigator.userAgent.indexOf('Trident') > -1;
        var L = this.options.sliderL + this.options.sliderR * 2 + 3; // 滑块实际边长
        var drawImg = function (ctx, operation) {
            var l = that.options.sliderL;
            var r = that.options.sliderR;
            var PI = that.options.PI;
            var x = that.x;
            var y = that.y;
            ctx.beginPath();
            ctx.moveTo(x, y);
            ctx.arc(x + l / 2, y - r + 2, r, 0.72 * PI, 2.26 * PI);
            ctx.lineTo(x + l, y);
            ctx.arc(x + l + r - 2, y + l / 2, r, 1.21 * PI, 2.78 * PI);
            ctx.lineTo(x + l, y + l);
            ctx.lineTo(x, y + l);
            ctx.arc(x + r - 2, y + l / 2, r + 0.4, 2.76 * PI, 1.24 * PI, true);
            ctx.lineTo(x, y);
            ctx.lineWidth = 2.4;
            ctx.fillStyle = 'rgba(255, 255, 255, 0.96)';
            ctx.strokeStyle = 'rgba(76, 59, 116, 0.52)';
            ctx.shadowColor = 'rgba(76, 59, 116, 0.18)';
            ctx.shadowBlur = 8;
            ctx.stroke();
            ctx[operation]();
            ctx.shadowColor = 'transparent';
            ctx.shadowBlur = 0;
            ctx.globalCompositeOperation = isIE ? 'xor' : 'destination-over';
        };

        var getRandomNumberByRange = function (start, end) {
            return Math.round(Math.random() * (end - start) + start);
        };
        var img = new Image();
        img.crossOrigin = "Anonymous";
        var loadCount = 0;
        img.onload = function () {
            // 随机创建滑块的位置
            that.x = typeof that.options.puzzleX === 'number'
                ? that.options.puzzleX
                : getRandomNumberByRange(L + 10, that.options.width - (L + 10));
            that.y = typeof that.options.puzzleY === 'number'
                ? that.options.puzzleY
                : getRandomNumberByRange(10 + that.options.sliderR * 2, that.options.height - (L + 10));
            drawImg(that.canvasCtx, 'fill');
            drawImg(that.blockCtx, 'clip');

            that.canvasCtx.drawImage(img, 0, 0, that.options.width - 2, that.options.height);
            that.blockCtx.drawImage(img, 0, 0, that.options.width - 2, that.options.height);
            var y = that.y - that.options.sliderR * 2 - 1;
            var ImageData = that.blockCtx.getImageData(that.x - 3, y, L, L);
            that.block.width = L;
            that.blockCtx.putImageData(ImageData, 0, y + 1);
            that.text.textContent = that.text.getAttribute('data-text');
        };
        img.onerror = function () {
            loadCount++;
            if (window.location.protocol === 'file:') {
                loadCount = that.options.maxLoadCount;
                console.error("can't load pic resource file from File protocal. Please try http or https");
            }
            if (loadCount >= that.options.maxLoadCount) {
                that.text.textContent = '加载失败';
                that.text.classList.add('text-danger');
                return;
            }
            img.src = that.options.localImages();
        };
        img.setSrc = function () {
            var src = '';
            loadCount = 0;
            that.text.classList.remove('text-danger');
            if (isFunction(that.options.setSrc)) src = that.options.setSrc();
            if ((!src || src === '') && that.options.imageUrl) src = that.options.imageUrl;
            if (!src || src === '') src = 'https://picsum.photos/' + that.options.width + '/' + that.options.height + '/?image=' + Math.round(Math.random() * 20);
            if (isIE) { // IE浏览器无法通过img.crossOrigin跨域，使用ajax获取图片blob然后转为dataURL显示
                var xhr = new XMLHttpRequest();
                xhr.onloadend = function (e) {
                    var file = new FileReader(); // FileReader仅支持IE10+
                    file.readAsDataURL(e.target.response);
                    file.onloadend = function (e) {
                        img.src = e.target.result;
                    };
                };
                xhr.open('GET', src);
                xhr.responseType = 'blob';
                xhr.send();
            } else img.src = src;
        };
        img.setSrc();
        this.text.setAttribute('data-text', this.options.barText);
        this.text.textContent = this.options.loadingText;
        this.img = img;
    };

    _proto.clean = function () {
        this.canvasCtx.clearRect(0, 0, this.options.width, this.options.height);
        this.blockCtx.clearRect(0, 0, this.options.width, this.options.height);
        this.block.width = this.options.width;
    };

    _proto.bindEvents = function () {
        var that = this;
        this.$element.addEventListener('selectstart', function () {
            return false;
        });

        this.refreshIcon.addEventListener('click', function () {
            if (isFunction(that.options.onRefresh)) {
                that.options.onRefresh.call(that.$element, that);
                return;
            }
            that.text.textContent = that.options.barText;
            that.reset();
        });

        var originX, originY, trail = [],
            isMouseDown = false;

        var clamp = function (value, min, max) {
            return Math.max(min, Math.min(value, max));
        };

        var sliderLimits = function () {
            var sliderWidth = that.slider.offsetWidth || 40;
            var blockWidth = that.options.sliderL + that.options.sliderR * 2 + 3;
            return {
                maxSliderLeft: Math.max(0, that.options.width - sliderWidth),
                maxBlockLeft: Math.max(0, that.options.width - blockWidth)
            };
        };

        var setSliderValue = function (sliderLeft, blockLeft) {
            that.slider.style.left = (sliderLeft - 1) + 'px';
            that.block.style.left = blockLeft + 'px';
            that.sliderMask.style.width = (sliderLeft + 4) + 'px';
            that.slider.setAttribute('aria-valuemax', String(sliderLimits().maxBlockLeft));
            that.slider.setAttribute('aria-valuenow', String(blockLeft));
        };

        var setDragPosition = function (moveX) {
            var limits = sliderLimits();
            var sliderLeft = clamp(moveX, 0, limits.maxSliderLeft);
            var blockLeft = limits.maxSliderLeft > 0
                ? Math.round((limits.maxBlockLeft / limits.maxSliderLeft) * sliderLeft)
                : 0;
            setSliderValue(sliderLeft, blockLeft);
        };

        var setBlockPosition = function (nextBlockLeft) {
            var limits = sliderLimits();
            var blockLeft = clamp(nextBlockLeft, 0, limits.maxBlockLeft);
            var sliderLeft = limits.maxBlockLeft > 0
                ? Math.round((limits.maxSliderLeft / limits.maxBlockLeft) * blockLeft)
                : 0;
            setSliderValue(sliderLeft, blockLeft);
        };

        var prepareVerification = function () {
            that.sliderContainer.classList.remove('sliderContainer_fail');
            that.sliderContainer.classList.remove('sliderContainer_success');
            that.sliderContainer.classList.remove('sliderContainer_resetting');
            that.sliderContainer.classList.add('sliderContainer_active');
            that.text.textContent = that.options.barText;
        };

        var finishVerification = function () {
            that.sliderContainer.classList.remove('sliderContainer_active');
            that.sliderContainer.classList.remove('sliderContainer_dragging');
            that.trail = trail.slice(0);
            var data = that.verify();
            if (data.spliced && data.verified) {
                that.sliderContainer.classList.add('sliderContainer_success');
                if (isFunction(that.options.onSuccess)) that.options.onSuccess.call(that.$element, data, that);
                return;
            }
            that.sliderContainer.classList.add('sliderContainer_fail');
            that.sliderContainer.classList.add('sliderContainer_resetting');
            if (isFunction(that.options.onFail)) that.options.onFail.call(that.$element, data, that);
            setTimeout(function () {
                that.text.innerHTML = that.options.failedText;
                that.reset();
            }, 620);
        };

        var pushKeyboardTrail = function () {
            var offset = trail.length % 4;
            trail.push(offset < 2 ? offset : 1 - offset);
        };

        var handleDragStart = function (e) {
            if (that.text.classList.contains('text-danger')) return;
            if (e.cancelable) e.preventDefault();
            var point = e.touches && e.touches.length ? e.touches[0] : e;
            originX = point.clientX;
            originY = point.clientY;
            trail = [];
            isMouseDown = true;
            prepareVerification();
            that.sliderContainer.classList.add('sliderContainer_dragging');
        };

        var handleDragMove = function (e) {
            if (!isMouseDown) return false;
            if (e.cancelable) e.preventDefault();
            var point = e.touches && e.touches.length ? e.touches[0] : e;
            var eventX = point.clientX;
            var eventY = point.clientY;
            var moveX = eventX - originX;
            var moveY = eventY - originY;
            var sliderWidth = that.slider.offsetWidth || 40;
            var maxSliderLeft = that.options.width - sliderWidth;
            setDragPosition(clamp(moveX, 0, maxSliderLeft));
            trail.push(Math.round(moveY));
        };

        var handleDragEnd = function (e) {
            if (!isMouseDown) return false;
            isMouseDown = false;
            if (e.cancelable) e.preventDefault();
            var point = e.changedTouches && e.changedTouches.length ? e.changedTouches[0] : e;
            var eventX = point.clientX;
            if (Math.abs(eventX - originX) < 1) {
                that.sliderContainer.classList.remove('sliderContainer_active');
                that.sliderContainer.classList.remove('sliderContainer_dragging');
                return false;
            }
            finishVerification();
        };

        var handleKeyboardMove = function (delta) {
            if (that.text.classList.contains('text-danger')) return;
            if (!that.sliderContainer.classList.contains('sliderContainer_active')) {
                trail = [];
                prepareVerification();
            }
            var currentLeft = parseInt(that.block.style.left, 10) || 0;
            setBlockPosition(currentLeft + delta);
            pushKeyboardTrail();
        };

        var handleKeyboardEnd = function () {
            var currentLeft = parseInt(that.block.style.left, 10) || 0;
            if (currentLeft < 1 || trail.length === 0) {
                that.sliderContainer.classList.remove('sliderContainer_active');
                return;
            }
            finishVerification();
        };

        setBlockPosition(0);

        var touchOptions = {passive: false};
        this.slider.addEventListener('mousedown', handleDragStart);
        this.slider.addEventListener('touchstart', handleDragStart, touchOptions);
        this.slider.addEventListener('keydown', function (e) {
            var key = e.key || '';
            if (key === 'ArrowRight' || key === 'Right') {
                e.preventDefault();
                e.stopPropagation();
                handleKeyboardMove(e.shiftKey ? 10 : 1);
                return;
            }
            if (key === 'ArrowLeft' || key === 'Left') {
                e.preventDefault();
                e.stopPropagation();
                handleKeyboardMove(e.shiftKey ? -10 : -1);
                return;
            }
            if (key === 'Enter' || key === ' ') {
                e.preventDefault();
                e.stopPropagation();
                handleKeyboardEnd();
            }
        });
        document.addEventListener('mousemove', handleDragMove);
        document.addEventListener('touchmove', handleDragMove, touchOptions);
        document.addEventListener('mouseup', handleDragEnd);
        document.addEventListener('touchend', handleDragEnd, touchOptions);

        document.addEventListener('mousedown', function () { return false; });
        document.addEventListener('touchstart', function () { return false; });
        document.addEventListener('swipe', function () { return false; });
    };

    _proto.verify = function () {
        var arr = this.trail || []; // 拖动时y轴的移动距离
        var left = parseInt(this.block.style.left, 10) || 0;
        var verified = false;
        if (arr.length === 0) {
            return {
                spliced: false,
                verified: false,
                left: left,
                trail: [],
                puzzleX: this.x,
                puzzleY: this.y
            };
        }
        if (this.options.remoteUrl !== null) {
            verified = this.options.verify(arr, this.options.remoteUrl);
        }
        else {
            var sum = function (x, y) { return x + y; };
            var square = function (x) { return x * x; };
            var average = arr.reduce(sum) / arr.length;
            var deviations = arr.map(function (x) { return x - average; });
            var stddev = Math.sqrt(deviations.map(square).reduce(sum) / arr.length);
            verified = stddev !== 0;
        }
        return {
            spliced: Math.abs(left - this.x) <= this.options.offset,
            verified: verified,
            left: left,
            trail: arr.slice(0),
            puzzleX: this.x,
            puzzleY: this.y
        };
    };

    _proto.reset = function () {
        this.sliderContainer.classList.remove('sliderContainer_fail');
        this.sliderContainer.classList.remove('sliderContainer_success');
        this.sliderContainer.classList.remove('sliderContainer_dragging');
        this.sliderContainer.classList.add('sliderContainer_resetting');
        this.slider.style.left = 0;
        this.block.style.left = 0;
        this.sliderMask.style.width = 0;
        this.slider.setAttribute('aria-valuenow', '0');
        this.clean();
        this.text.setAttribute('data-text', this.options.barText);
        this.text.textContent = this.options.loadingText;
        this.img.setSrc();
        var that = this;
        setTimeout(function () {
            that.sliderContainer.classList.remove('sliderContainer_resetting');
        }, 260);
    };
})();
