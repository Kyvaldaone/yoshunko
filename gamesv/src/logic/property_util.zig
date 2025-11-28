const std = @import("std");
const Assets = @import("../data/Assets.zig");
const Player = @import("../fs/Player.zig");
const Avatar = @import("../fs/Avatar.zig");
const Equip = @import("../fs/Equip.zig");
const Allocator = std.mem.Allocator;
const PropMap = std.AutoArrayHashMapUnmanaged(PropertyType, i32);

const templates = @import("../data/templates.zig");
const WeaponTemplate = templates.WeaponTemplate;
const WeaponLevelTemplate = templates.WeaponLevelTemplate;
const WeaponStarTemplate = templates.WeaponStarTemplate;
const AvatarBattleTemplate = templates.AvatarBattleTemplate;
const AvatarPassiveSkillTemplate = templates.AvatarPassiveSkillTemplate;
const AvatarLevelAdvanceTemplate = templates.AvatarLevelAdvanceTemplate;

const log = std.log.scoped(.prop_calc);

pub const Errors = error{
    AvatarNotUnlocked,
    MissingBattleTemplate,
    MissingLevelAdvanceTemplate,
    MissingWeaponTemplate,
    MissingWeaponLevelTemplate,
    MissingWeaponStarTemplate,
};

pub fn makePropertyMap(player: *const Player, arena: Allocator, assets: *const Assets, avatar_id: u32) !PropMap {
var map: PropMap = .empty;

const avatar = player.avatar_map.getPtr(avatar_id) orelse return Errors.AvatarNotUnlocked;

const battle_template = assets.templates.getConfigByKey(.avatar_battle_template_tb, avatar_id) orelse return Errors.MissingBattleTemplate;
try initBaseProperties(&map, arena, battle_template);

const level_advance_template = assets.templates.getAvatarLevelAdvanceTemplate(avatar_id, avatar.rank) orelse return Errors.MissingLevelAdvanceTemplate;
try initLevelAdvanceProperties(&map, arena, &level_advance_template);

try growPropertyByLevel(&map, arena, avatar.level, PropertyType.HpMaxBase, PropertyType.HpMaxGrowth, PropertyType.HpMaxAdvance);
try growPropertyByLevel(&map, arena, avatar.level, PropertyType.AtkBase, PropertyType.AtkGrowth, PropertyType.AtkAdvance);
try growPropertyByLevel(&map, arena, avatar.level, PropertyType.DefBase, PropertyType.DefGrowth, PropertyType.DefAdvance);

if (assets.templates.getAvatarPassiveSkillTemplate(avatar_id, avatar.passive_skill_level)) |passive_skill_template| {
    try applyPassiveSkillProperties(&map, arena, passive_skill_template);
}

if (avatar.cur_weapon_uid != 0) blk: {
    const info = player.weapon_map.getPtr(avatar.cur_weapon_uid) orelse break :blk;
    const weapon_template = assets.templates.getConfigByKey(.weapon_template_tb, info.id) orelse return Errors.MissingWeaponTemplate;
    const rarity: u32 = @mod(@divFloor(info.id, 1000), 10);

    const level_template = assets.templates.getWeaponLevelTemplate(rarity, info.level) orelse return Errors.MissingWeaponLevelTemplate;
    const star_template = assets.templates.getWeaponStarTemplate(rarity, info.star) orelse return Errors.MissingWeaponStarTemplate;

    try initWeaponProperties(&map, arena, weapon_template, &level_template, &star_template);
}

var equipment: [Avatar.equipment_count]*const Equip = undefined;
var equipment_count: usize = 0;
for (avatar.dressed_equip) |maybe_equip_uid| if (maybe_equip_uid) |equip_uid| {
    if (player.equip_map.getPtr(equip_uid)) |equip| {
        equipment[equipment_count] = equip;
        equipment_count += 1;
    }
};

try initEquipmentProperties(&map, arena, equipment[0..equipment_count], assets);
try initEquipmentSuitProperties(&map, arena, equipment[0..equipment_count], assets);

try setDynamicProperties(&map, arena);
try applyCoreSkillBonus(&map, arena, avatar_id, avatar.skill_type_level[@intFromEnum(Avatar.SkillLevel.Type.core_skill)].level);

clearCustomProperties(&map);
try setBattleProperties(&map, arena);

return map;

}

fn applyCoreSkillBonus(map: *PropMap, arena: Allocator, id: u32, level: u32) !void {
    inline for (core_skill_specials) |bonus| {
        const avatar_id = bonus.@"0";
        const bonus_prop = bonus.@"1";
        const scale_prop = bonus.@"2";
        const percentage = bonus.@"3";

        if (avatar_id == id) {
            if (level == 0 or level > percentage.len) return Errors.AvatarNotUnlocked;

            const scale_value = getProperty(map, scale_prop);
            const bonus_value = @divFloor(scale_value * percentage[level - 1], 100);
            try modifyProperty(map, arena, bonus_prop, bonus_value);
        }
    }
}

fn initEquipmentSuitProperties(map: *PropMap, arena: Allocator, equipment: []const ?*const Equip, assets: *const Assets) !void {
var suit_times: [Avatar.equipment_count]struct { u32, u32 } = undefined;
var suit_count: usize = 0;

for (equipment) |item| {
    if (item) |equip| {
        const suit_id = ((equip.id / 100) * 100);
        var found: bool = false;
        for (suit_times[0..suit_count]) |*entry| {
            if (entry.@"0" == suit_id) {
                entry.@"1" += 1;
                found = true;
                break;
            }
        }
        if (!found) {
            suit_times[suit_count] = .{ suit_id, 1 };
            suit_count += 1;
        }
    }
}

for (suit_times[0..suit_count]) |suit| {
    const suit_id = suit.@"0";
    const count = suit.@"1";
    if (assets.templates.getConfigByKey(.equipment_suit_template_tb, suit_id)) |suit_template| {
        if (count >= suit_template.primary_condition) {
            for (suit_template.primary_suit_propertys) |prop| {
                const property = std.meta.intToEnum(PropertyType, prop.property) catch {
                    log.debug("initEquipmentSuitProperties: invalid property {} in suit {}", .{ prop.property, suit_id });
                    continue;
                };
                try modifyProperty(map, arena, property, prop.value);
            }
        }
    }
}

}

fn initEquipmentProperties(map: *PropMap, arena: Allocator, equipment: []const *const Equip, assets: *const Assets) !void {
const divisor: f32 = 10_000;

for (equipment) |equip| {
    const rarity: u32 = (equip.id / 10) % 10;
    const level_template = assets.templates.getEquipmentLevelTemplate(rarity, equip.level);
    const rate: f32 = if (level_template) |template| @floatFromInt(template.property_rate) else 1;

    for (equip.properties) |prop| {
        if (prop) |property| {
            const key = std.meta.intToEnum(PropertyType, property.key) catch {
                log.debug("initEquipmentProperties: invalid property {} in equip {}", .{ property.key, equip.id });
                continue;
            };

            const base: f32 = @floatFromInt(property.base_value);
            const value: i32 = @intFromFloat(base + (base * rate / divisor));
            try modifyProperty(map, arena, key, value);
        }
    }

    for (equip.sub_properties) |prop| {
        if (prop) |property| {
            const key = std.meta.intToEnum(PropertyType, property.key) catch {
                log.debug("initEquipmentProperties: invalid sub_property {} in equip {}", .{ property.key, equip.id });
                continue;
            };

            const base: f32 = @floatFromInt(property.base_value);
            const add: f32 = @floatFromInt(property.add_value);
            try modifyProperty(map, arena, key, @intFromFloat(base * add));
        }
    }
}

}

fn initWeaponProperties(map: *PropMap, arena: Allocator, weapon: *const WeaponTemplate, level: *const WeaponLevelTemplate, star: *const WeaponStarTemplate) !void {
const divisor: f32 = 10_000;

const level_rate: f32 = @floatFromInt(level.rate);
const star_rate: f32 = @floatFromInt(star.star_rate);
const rand_rate: f32 = @floatFromInt(star.rand_rate);

const base_property_base_value: f32 = @floatFromInt(weapon.base_property.value);
const base_property_level_rate: i32 = @intFromFloat((base_property_base_value * level_rate) / divisor);
const base_property_star_rate: i32 = @intFromFloat((base_property_base_value * star_rate) / divisor);

if (std.meta.intToEnum(PropertyType, weapon.base_property.property) catch null) |base_property| {
    try modifyProperty(map, arena, base_property, @as(i32, @intFromFloat(base_property_base_value)) + base_property_level_rate + base_property_star_rate);
} else {
    log.err("weapon base property is invalid: {} (weapon_id: {})", .{ weapon.base_property.property, weapon.item_id });
}

const rand_property_base_value: f32 = @floatFromInt(weapon.rand_property.value);
const rand_property_rate: i32 = @intFromFloat((rand_property_base_value * rand_rate) / divisor);

if (std.meta.intToEnum(PropertyType, weapon.rand_property.property) catch null) |rand_property| {
    try modifyProperty(map, arena, rand_property, @as(i32, @intFromFloat(rand_property_base_value)) + rand_property_rate);
} else {
    log.err("weapon rand property is invalid: {} (weapon_id: {})", .{ weapon.rand_property.property, weapon.item_id });
}

}

fn setBattleProperties(map: *PropMap, arena: Allocator) !void {
try modifyProperty(map, arena, PropertyType.SkipDefAtk, @divFloor(getProperty(map, PropertyType.Atk) * 30, 100));

try setProperty(map, arena, PropertyType.HpMaxBattle, getProperty(map, PropertyType.HpMax));
try setProperty(map, arena, PropertyType.AtkBattle, getProperty(map, PropertyType.Atk));
try setProperty(map, arena, PropertyType.BreakStunBattle, getProperty(map, PropertyType.BreakStun));
try setProperty(map, arena, PropertyType.SkipDefAtkBattle, getProperty(map, PropertyType.SkipDefAtk));
try setProperty(map, arena, PropertyType.DefBattle, getProperty(map, PropertyType.Def));
try setProperty(map, arena, PropertyType.CritBattle, getProperty(map, PropertyType.Crit));
try setProperty(map, arena, PropertyType.CritDmgBattle, getProperty(map, PropertyType.CritDmg));
try setProperty(map, arena, PropertyType.SpRecoverBattle, getProperty(map, PropertyType.SpRecover));
try setProperty(map, arena, PropertyType.ElementMysteryBattle, getProperty(map, PropertyType.ElementMystery));
try setProperty(map, arena, PropertyType.ElementAbnormalPowerBattle, getProperty(map, PropertyType.ElementAbnormalPower));
try setProperty(map, arena, PropertyType.AddedDamageRatioBattle, getProperty(map, PropertyType.AddedDamageRatio));
try setProperty(map, arena, PropertyType.AddedDamageRatioPhysicsBattle, getProperty(map, PropertyType.AddedDamageRatioPhysics));
try setProperty(map, arena, PropertyType.AddedDamageRatioFireBattle, getProperty(map, PropertyType.AddedDamageRatioFire));
try setProperty(map, arena, PropertyType.AddedDamageRatioIceBattle, getProperty(map, PropertyType.AddedDamageRatioIce));
try setProperty(map, arena, PropertyType.AddedDamageRatioElecBattle, getProperty(map, PropertyType.AddedDamageRatioElec));
try setProperty(map, arena, PropertyType.AddedDamageRatioEtherBattle, getProperty(map, PropertyType.AddedDamageRatioEther));
try setProperty(map, arena, PropertyType.RpRecoverBattle, getProperty(map, PropertyType.RpRecover));
try setProperty(map, arena, PropertyType.SkipDefDamageRatioBattle, getProperty(map, PropertyType.SkipDefDamageRatio));
try modifyProperty(map, arena, PropertyType.PenRatioBattle, getProperty(map, PropertyType.Pen));
try modifyProperty(map, arena, PropertyType.PenDeltaBattle, getProperty(map, PropertyType.PenValue));

try modifyProperty(map, arena, PropertyType.Hp, getProperty(map, PropertyType.HpMax));

}

fn setDynamicProperties(map: *PropMap, arena: Allocator) !void {
try setDynamicProperty(map, arena, PropertyType.HpMax, PropertyType.HpMaxBase, PropertyType.HpMaxRatio, PropertyType.HpMaxDelta);
try setDynamicProperty(map, arena, PropertyType.SpMax, PropertyType.SpMaxBase, PropertyType.None, PropertyType.SpMaxDelta);
try setDynamicProperty(map, arena, PropertyType.Atk, PropertyType.AtkBase, PropertyType.AtkRatio, PropertyType.AtkDelta);
try setDynamicProperty(map, arena, PropertyType.BreakStun, PropertyType.BreakStunBase, PropertyType.BreakStunRatio, PropertyType.BreakStunDelta);
try setDynamicProperty(map, arena, PropertyType.SkipDefAtk, PropertyType.SkipDefAtkBase, PropertyType.None, PropertyType.SkipDefAtkDelta);
try setDynamicProperty(map, arena, PropertyType.Def, PropertyType.DefBase, PropertyType.DefRatio, PropertyType.DefDelta);
try setDynamicProperty(map, arena, PropertyType.Crit, PropertyType.CritBase, PropertyType.None, PropertyType.CritDelta);
try setDynamicProperty(map, arena, PropertyType.CritDmg, PropertyType.CritDmgBase, PropertyType.None, PropertyType.CritDmgDelta);
try setDynamicProperty(map, arena, PropertyType.Pen, PropertyType.PenBase, PropertyType.None, PropertyType.PenDelta);
try setDynamicProperty(map, arena, PropertyType.PenValue, PropertyType.PenValueBase, PropertyType.None, PropertyType.PenValueDelta);
try setDynamicProperty(map, arena, PropertyType.SpRecover, PropertyType.SpRecoverBase, PropertyType.SpRecoverRatio, PropertyType.SpRecoverDelta);
try setDynamicProperty(map, arena, PropertyType.RpRecover, PropertyType.RpRecoverBase, PropertyType.RpRecoverRatio, PropertyType.RpRecoverDelta);
try setDynamicProperty(map, arena, PropertyType.ElementMystery, PropertyType.ElementMysteryBase, PropertyType.None, PropertyType.ElementMysteryDelta);
try setDynamicProperty(map, arena, PropertyType.ElementAbnormalPower, PropertyType.ElementAbnormalPowerBase, PropertyType.ElementAbnormalPowerRatio, PropertyType.ElementAbnormalPowerDelta);
try setDynamicProperty(map, arena, PropertyType.AddedDamageRatio, PropertyType.AddedDamageRatio1, PropertyType.None, PropertyType.AddedDamageRatio3);
try setDynamicProperty(map, arena, PropertyType.AddedDamageRatioPhysics, PropertyType.AddedDamageRatioPhysics1, PropertyType.None, PropertyType.AddedDamageRatioPhysics3);
try setDynamicProperty(map, arena, PropertyType.AddedDamageRatioFire, PropertyType.AddedDamageRatioFire1, PropertyType.None, PropertyType.AddedDamageRatioFire3);
try setDynamicProperty(map, arena, PropertyType.AddedDamageRatioIce, PropertyType.AddedDamageRatioIce1, PropertyType.None, PropertyType.AddedDamageRatioIce3);
try setDynamicProperty(map, arena, PropertyType.AddedDamageRatioElec, PropertyType.AddedDamageRatioElec1, PropertyType.None, PropertyType.AddedDamageRatioElec3);
try setDynamicProperty(map, arena, PropertyType.AddedDamageRatioEther, PropertyType.AddedDamageRatioEther1, PropertyType.None, PropertyType.AddedDamageRatioEther3);
try setDynamicProperty(map, arena, PropertyType.SkipDefDamageRatio, PropertyType.SkipDefDamageRatio1, PropertyType.None, PropertyType.SkipDefDamageRatio3);
}

fn setDynamicProperty(map: *PropMap, arena: Allocator, prop: PropertyType, base_prop: PropertyType, ratio_prop: PropertyType, delta_prop: PropertyType) !void {
const divisor: f32 = 10_000.0;

const base = getProperty(map, base_prop);
const delta = getProperty(map, delta_prop);

const base_float: f32 = @floatFromInt(base);
const ratio: f32 = @floatFromInt(getProperty(map, ratio_prop));

var scaled_base = (base_float * ratio) / divisor;
if (prop == PropertyType.HpMax) {
    scaled_base = @ceil(scaled_base);
}

try setProperty(map, arena, prop, base + @as(i32, @intFromFloat(scaled_base)) + delta);

}

fn applyPassiveSkillProperties(map: *PropMap, arena: Allocator, template: *const AvatarPassiveSkillTemplate) !void {
for (template.propertys) |prop| {
const key = std.meta.intToEnum(PropertyType, prop.property) catch {
log.err("invalid property type encountered: {}", .{prop.property});
continue;
};
try modifyProperty(map, arena, key, prop.value);
}
}

fn growPropertyByLevel(map: *PropMap, arena: Allocator, level: u32, base_prop: PropertyType, growth_prop: PropertyType, advance_prop: PropertyType) !void {
const divisor: f32 = 10_000.0;

const base = map.get(base_prop).?;
const advance = map.get(advance_prop).?;
const growth: f32 = @floatFromInt(map.get(growth_prop).?);
const level_float: f32 = @floatFromInt(level - 1);

const add: i32 = @intFromFloat((level_float * growth) / divisor);
try setProperty(map, arena, base_prop, base + add + advance);

}

fn initLevelAdvanceProperties(map: *PropMap, arena: Allocator, template: *const AvatarLevelAdvanceTemplate) !void {
try setProperty(map, arena, PropertyType.HpMaxAdvance, template.hp_max);
try setProperty(map, arena, PropertyType.AtkAdvance, template.attack);
try setProperty(map, arena, PropertyType.DefAdvance, template.defence);
}

fn initBaseProperties(map: *PropMap, arena: Allocator, template: *const AvatarBattleTemplate) !void {
try setProperty(map, arena, PropertyType.HpMaxBase, template.hp_max);
try setProperty(map, arena, PropertyType.HpMaxGrowth, template.health_growth);
try setProperty(map, arena, PropertyType.AtkBase, template.attack);
try setProperty(map, arena, PropertyType.AtkGrowth, template.attack_growth);
try setProperty(map, arena, PropertyType.BreakStunBase, template.break_stun);
try setProperty(map, arena, PropertyType.DefBase, template.defence);
try setProperty(map, arena, PropertyType.DefGrowth, template.defence_growth);
try setProperty(map, arena, PropertyType.CritBase, template.crit);
try setProperty(map, arena, PropertyType.CritDmgBase, template.crit_damage);
try setProperty(map, arena, PropertyType.PenBase, 0);
try setProperty(map, arena, PropertyType.PenValueBase, 0);
try setProperty(map, arena, PropertyType.SpMaxBase, template.sp_bar_point);
try setProperty(map, arena, PropertyType.SpRecoverBase, template.sp_recover);
try setProperty(map, arena, PropertyType.ElementMysteryBase, template.element_mystery);
try setProperty(map, arena, PropertyType.ElementAbnormalPowerBase, template.element_abnormal_power);
try setProperty(map, arena, PropertyType.RpMax, template.rp_max);
try setProperty(map, arena, PropertyType.RpRecoverBase, template.rp_recover);
}

fn modifyProperty(map: *PropMap, arena: Allocator, key: PropertyType, delta: i32) !void {
const current = map.get(key) orelse 0;
try setProperty(map, arena, key, current + delta);
}

fn setProperty(map: *PropMap, arena: Allocator, key: PropertyType, value: i32) !void {
try map.put(arena, key, value);
}

fn getProperty(map: *const PropMap, key: PropertyType) i32 {
return map.get(key) orelse 0;
}

fn clearCustomProperties(map: *PropMap) void {
_ = map.swapRemove(PropertyType.HpMaxGrowth);
_ = map.swapRemove(PropertyType.AtkGrowth);
_ = map.swapRemove(PropertyType.DefGrowth);
_ = map.swapRemove(PropertyType.HpMaxAdvance);
_ = map.swapRemove(PropertyType.AtkAdvance);
_ = map.swapRemove(PropertyType.DefAdvance);
}

const core_skill_specials = [_]struct { u32, PropertyType, PropertyType, [7]i32 }{
.{ 1051, PropertyType.SkipDefAtk, PropertyType.HpMax, .{ 10, 10, 10, 10, 10, 10, 10 } },
.{ 1121, PropertyType.Atk, PropertyType.Def, .{ 40, 46, 52, 60, 66, 72, 80 } },
.{ 1371, PropertyType.SkipDefAtk, PropertyType.HpMax, .{ 10, 10, 10, 10, 10, 10, 10 } },
.{ 1441, PropertyType.SkipDefAtk, PropertyType.HpMax, .{ 10, 10, 10, 10, 10, 10, 10 } },
.{ 1471, PropertyType.SkipDefAtk, PropertyType.HpMax, .{ 10, 10, 10, 10, 10, 10, 10 } },
};

pub const PropertyType = enum(u32) {
None = 0,
Hp = 1,
HpMax = 111,
SpMax = 115,
RpMax = 119,
Atk = 121,
BreakStun = 122,
SkipDefAtk = 123,
Def = 131,
Crit = 201,
CritDmg = 211,
Pen = 231,
PenValue = 232,
SpRecover = 305,
AddedDamageRatio = 307,
ElementMystery = 312,
ElementAbnormalPower = 314,
AddedDamageRatioPhysics = 315,
AddedDamageRatioFire = 316,
AddedDamageRatioIce = 317,
AddedDamageRatioElec = 318,
AddedDamageRatioEther = 319,
RpRecover = 320,
SkipDefDamageRatio = 322,
HpMaxBattle = 1111,
AtkBattle = 1121,
BreakStunBattle = 1122,
SkipDefAtkBattle = 1123,
DefBattle = 1131,
CritBattle = 1201,
CritDmgBattle = 1211,
PenRatioBattle = 1231,
PenDeltaBattle = 1232,
SpRecoverBattle = 1305,
AddedDamageRatioBattle = 1307,
ElementMysteryBattle = 1312,
ElementAbnormalPowerBattle = 1314,
AddedDamageRatioPhysicsBattle = 1315,
AddedDamageRatioFireBattle = 1316,
AddedDamageRatioIceBattle = 1317,
AddedDamageRatioElecBattle = 1318,
AddedDamageRatioEtherBattle = 1319,
RpRecoverBattle = 1320,
SkipDefDamageRatioBattle = 1322,
HpMaxBase = 11101,
SpMaxBase = 11501,
AtkBase = 12101,
BreakStunBase = 12201,
SkipDefAtkBase = 12301,
DefBase = 13101,
CritBase = 20101,
CritDmgBase = 21101,
PenBase = 23101,
PenValueBase = 23201,
SpRecoverBase = 30501,
ElementMysteryBase = 31201,
ElementAbnormalPowerBase = 31401,
RpRecoverBase = 32001,
HpMaxRatio = 11102,
AtkRatio = 12102,
BreakStunRatio = 12202,
DefRatio = 13102,
SpRecoverRatio = 30502,
ElementAbnormalPowerRatio = 31402,
RpRecoverRatio = 32002,
HpMaxDelta = 11103,
SpMaxDelta = 11503,
AtkDelta = 12103,
BreakStunDelta = 12203,
SkipDefAtkDelta = 12303,
DefDelta = 13103,
CritDelta = 20103,
CritDmgDelta = 21103,
PenDelta = 23103,
PenValueDelta = 23203,
SpRecoverDelta = 30503,
ElementMysteryDelta = 31203,
ElementAbnormalPowerDelta = 31403,
RpRecoverDelta = 32003,
AddedDamageRatio1 = 30701,
AddedDamageRatio3 = 30703,
AddedDamageRatioPhysics1 = 31501,
AddedDamageRatioPhysics3 = 31503,
AddedDamageRatioFire1 = 31601,
AddedDamageRatioFire3 = 31603,
AddedDamageRatioIce1 = 31701,
AddedDamageRatioIce3 = 31703,
AddedDamageRatioElec1 = 31801,
AddedDamageRatioElec3 = 31803,
AddedDamageRatioEther1 = 31901,
AddedDamageRatioEther3 = 31903,
SkipDefDamageRatio1 = 32201,
SkipDefDamageRatio3 = 32203,
HpMaxGrowth = 99991110,
AtkGrowth = 99991210,
DefGrowth = 99991310,
HpMaxAdvance = 99991111,
AtkAdvance = 99991211,
DefAdvance = 99991311,
};