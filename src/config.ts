import type {
  LicenseConfig,
  NavBarConfig,
  ProfileConfig,
  SiteConfig,
} from './types/config'
import { LinkPreset } from './types/config'

export const siteConfig: SiteConfig = {
  title: 'Sunset\'s Blog',
  subtitle: '记录',
  lang: 'zh_CN',         // 语言 Language ('en', 'zh_CN', 'zh_TW', 'ja', 'ko', 'es', 'th')
  themeColor: {
    hue: 250,         // 默认主题颜色的色相，范围 0 到 360 Default hue for the theme color, from 0 to 360
    fixed: false,     // 隐藏访客的主题颜色选择器 Hide the theme color picker for visitors
  },
  banner: {
    enable: true,   // 是否启用横幅 Enable the banner
    src: 'assets/images/banner.jpg',    // 横幅图片路径，相对于 /src 目录 Path of the banner image, relative to the /src directory
    position: 'top',      // 位置（'top', 'center', 'bottom'），默认 'center' Position ('top', 'center', 'bottom'), default is 'center'
    credit: {
      enable: false,         // 显示横幅图片的来源信息 Display the credit text of the banner image
      text: '',              // 信用文本 Credit text to be displayed
      url: ''                // （可选）原始作品或艺术家的页面链接 (Optional) URL link to the original artwork or artist's page
    }
  },
  toc: {
    enable: true,           // 显示文章右侧的目录 Display the table of contents on the right side of the post
    depth: 2                // 目录最大标题深度，范围 1 到 3 Maximum heading depth to show in the table, from 1 to 3
  },
  favicon: [    // 为空数组时使用默认 favicon Leave this array empty to use the default favicon
    // {
    //   src: '/favicon/icon.png',    // favicon 路径，相对于 /public 目录 Path of the favicon, relative to the /public directory
    //   theme: 'light',              // （可选）'light' 或 'dark' 模式专用的 favicon (Optional) Either 'light' or 'dark', set only if you have different favicons for each mode
    //   sizes: '32x32',              // （可选）favicon 的尺寸 (Optional) Size of the favicon
    // }
  ]
}

export const navBarConfig: NavBarConfig = {
  links: [
    LinkPreset.Home,      // 主页 Home
    LinkPreset.Archive,   // 归档 Archive
    LinkPreset.About,     // 关于 About
    {
      name: 'GitHub',
      url: 'https://github.com/sunset2131',  // 外部链接 External link
      external: true,                            // 显示外部链接图标，并在新标签页打开 Show an external link icon and open in a new tab
    },
  ],
}

export const profileConfig: ProfileConfig = {
  avatar: 'assets/images/demo-avatar.png',  // 头像路径，相对于 /src 目录 Path of the avatar image, relative to the /src directory
  name: 'Sunset',
  bio: 'Sunset dolor sit amet, consectetur adipiscing elit.',
  links: [
    {
      name: 'Twitter',
      icon: 'fa6-brands:twitter',       // 图标代码（https://icones.js.org/） Icon code (https://icones.js.org/)
                                        // 可能需要安装对应的图标集 You may need to install the corresponding icon set
                                        // `pnpm add @iconify-json/<icon-set-name>`
      url: 'https://twitter.com',
    },
    {
      name: 'Steam',
      icon: 'fa6-brands:steam',
      url: 'https://store.steampowered.com',
    },
    {
      name: 'GitHub',
      icon: 'fa6-brands:github',
      url: 'https://github.com/sunset2131',
    },
  ],
}

export const licenseConfig: LicenseConfig = {
  enable: true,  // 启用许可证信息 Enable license information
  name: 'CC BY-NC-SA 4.0',  // 许可证名称 License name
  url: 'https://creativecommons.org/licenses/by-nc-sa/4.0/', // 许可证链接 License URL
}
