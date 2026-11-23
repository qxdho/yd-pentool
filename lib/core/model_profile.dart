import 'dart:convert';

/// 机型档案：把"从哪里找脚本、用什么算法、怎么恢复"这些差异沉淀成数据，
/// 而不是散在代码分支里。新增机型 = 加一条 JSON。
class ModelProfile {
  ModelProfile({
    required this.id,
    required this.displayName,
    this.socHint = '',
    this.container = 'RKFW',
    this.rootfs = '',
    this.scriptPaths = const [],
    this.hashAlgorithms = const [],
    this.trailingNewline,
    this.flashMethods = const [],
    this.notes = '',
    this.observed = const {},
  });

  final String id;
  final String displayName;
  final String socHint;
  final String container;
  final String rootfs;
  final List<String> scriptPaths;
  final List<String> hashAlgorithms;

  /// null = 以脚本实际内容为准
  final bool? trailingNewline;

  /// `ota`（本地服务器劫持）/ `loader`（RKDevTool 线刷）/ `sdcard`
  final List<String> flashMethods;

  final String notes;

  /// 实测记录：脚本偏移、哈希偏移、原始哈希等。
  final Map<String, dynamic> observed;

  factory ModelProfile.fromJson(Map<String, dynamic> json) => ModelProfile(
        id: json['id'] as String,
        displayName: json['displayName'] as String? ?? json['id'] as String,
        socHint: json['socHint'] as String? ?? '',
        container: json['container'] as String? ?? 'RKFW',
        rootfs: json['rootfs'] as String? ?? '',
        scriptPaths: (json['scriptPaths'] as List?)?.cast<String>() ?? const [],
        hashAlgorithms:
            (json['hashAlgorithms'] as List?)?.cast<String>() ?? const [],
        trailingNewline: json['trailingNewline'] as bool?,
        flashMethods: (json['flashMethods'] as List?)?.cast<String>() ?? const [],
        notes: json['notes'] as String? ?? '',
        observed: (json['observed'] as Map?)?.cast<String, dynamic>() ?? const {},
      );
}

class ModelProfileDb {
  ModelProfileDb(this.profiles);

  final List<ModelProfile> profiles;

  factory ModelProfileDb.fromJsonString(String source) {
    final root = jsonDecode(source) as Map<String, dynamic>;
    final list = (root['profiles'] as List).cast<Map<String, dynamic>>();
    return ModelProfileDb(list.map(ModelProfile.fromJson).toList());
  }

  /// 用镜像里读到的线索做粗匹配；匹配不上也不影响使用，
  /// 因为扫描/改写完全依据脚本内容，profile 只用于提示与默认值。
  ModelProfile? guess({required String container, required List<String> algorithmNames}) {
    var best = -1;
    ModelProfile? hit;
    for (final p in profiles) {
      var score = 0;
      if (p.container == container) score += 2;
      for (final a in algorithmNames) {
        if (p.hashAlgorithms.contains(a)) score += 3;
      }
      if (score > best) {
        best = score;
        hit = p;
      }
    }
    return best > 0 ? hit : null;
  }
}
