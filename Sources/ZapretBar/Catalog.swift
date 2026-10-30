import Foundation

/// Сервис, который пользователь может «разблокировать» одним переключателем.
struct Service: Identifiable, Hashable {
    let id: String
    let name: String
    let symbol: String
    let note: String
    let domains: [String]
    /// Адреса, по которым проверяется доступность сервиса: всё должно открыться.
    let probeURLs: [String]
}

enum Catalog {
    static let services: [Service] = [
        Service(
            id: "youtube", name: "YouTube", symbol: "play.rectangle.fill",
            note: "Видео без замедления",
            domains: ["youtube.com", "youtu.be", "yt.be", "googlevideo.com", "ytimg.com",
                      "ggpht.com", "youtube-nocookie.com", "youtubei.googleapis.com",
                      "youtube.googleapis.com", "jnn-pa.googleapis.com", "wide-youtube.l.google.com",
                      "youtubekids.com", "play.google.com"],
            probeURLs: ["https://www.youtube.com/", "https://i.ytimg.com/"]),
        Service(
            id: "discord", name: "Discord", symbol: "bubble.left.and.bubble.right.fill",
            note: "Чаты и сайт (голос по UDP не поддерживается)",
            domains: ["discord.com", "discord.gg", "discordapp.com", "discordapp.net", "discord.media",
                      "discordcdn.com", "discord.dev", "discord.new", "discord.gift",
                      "discordstatus.com", "dis.gd", "discord.co"],
            probeURLs: ["https://discord.com/", "https://gateway.discord.gg/", "https://cdn.discordapp.com/"]),
        Service(
            id: "meta", name: "Instagram и Facebook", symbol: "camera.fill",
            note: "Может не помочь, если блокировка по IP",
            domains: ["instagram.com", "cdninstagram.com", "facebook.com", "fbcdn.net",
                      "fb.com", "fbsbx.com", "facebook.net", "threads.net", "threads.com"],
            probeURLs: ["https://www.instagram.com/"]),
        Service(
            id: "x", name: "X (Twitter)", symbol: "at",
            note: "Лента, картинки и видео",
            domains: ["x.com", "twitter.com", "twimg.com", "t.co"],
            probeURLs: ["https://x.com/"]),
        Service(
            id: "rutracker", name: "Rutracker", symbol: "arrow.down.circle.fill",
            note: "Сайт трекера",
            domains: ["rutracker.org", "rutracker.cc", "rutracker.net"],
            probeURLs: ["https://rutracker.org/"]),
        Service(
            id: "linkedin", name: "LinkedIn", symbol: "briefcase.fill",
            note: "Сайт и картинки",
            domains: ["linkedin.com", "licdn.com"],
            probeURLs: ["https://www.linkedin.com/"]),
    ]

    static func service(_ id: String) -> Service? { services.first { $0.id == id } }
}

/// Способ обхода DPI — набор параметров tpws с человеческим описанием.
struct Strategy: Identifiable, Hashable {
    let id: String
    let name: String
    let summary: String
    let args: [String]
    /// Нужна подмена ClientHello (доступ к /dev/bpf). Без него используется «С лишним байтом».
    var fake = false
}

extension Catalog {
    // Порядок важен: автоподбор идёт сверху вниз и останавливается на первом
    // способе, который быстро открыл всё. Подмена — первой: только она пробивает
    // Discord, X и другие сайты за Cloudflare (проверено scripts/fake-test.py без VPN).
    static let strategies: [Strategy] = [
        Strategy(
            id: "fake", name: "Подмена приветствия",
            summary: "Как zapret на Windows: фильтр видит поддельное приветствие от google.com, а сервер — настоящее. Открывает Discord, X и сайты на Cloudflare.",
            args: ["--split-pos=1,midsld", "--hostcase"], fake: true),
        Strategy(
            id: "fake_oob", name: "Подмена + лишний байт",
            summary: "Подмена приветствия вместе с «срочным» байтом — если одной подмены мало.",
            args: ["--split-pos=1,midsld", "--oob", "--hostcase"], fake: true),
        Strategy(
            id: "oob", name: "С лишним байтом",
            summary: "Делит начало соединения и добавляет «срочный» байт, который сбивает фильтр с толку.",
            args: ["--split-pos=1,midsld", "--oob", "--hostcase"]),
        Strategy(
            id: "standard", name: "Простой разрез",
            summary: "Только делит начало соединения. Помогает со старыми фильтрами.",
            args: ["--split-pos=1,midsld", "--hostcase"]),
        Strategy(
            id: "tlsrec1", name: "Две TLS-записи",
            summary: "Дополнительно делит приветствие TLS на две записи в самом начале.",
            args: ["--tlsrec=1", "--split-pos=1,midsld", "--hostcase"]),
        Strategy(
            id: "sni", name: "Разрез имени сайта",
            summary: "Режет TLS-запись внутри имени сайта. Некоторые провайдеры за это блокируют всё — проверьте.",
            args: ["--tlsrec=sniext+1", "--split-pos=1,midsld", "--hostcase"]),
        Strategy(
            id: "aggressive", name: "Максимальный",
            summary: "Всё сразу: много разрезов, TLS-запись и лишний байт. Для упрямых провайдеров.",
            args: ["--tlsrec=sniext+1", "--split-pos=1,host,midsld,endhost", "--oob", "--hostcase"]),
    ]

    static func strategy(_ id: String) -> Strategy { strategies.first { $0.id == id } ?? strategies[0] }
}
