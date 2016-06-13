/* packet-bzflag.c
 * Routines for BZflag protocol packet disassembly
 * By Steve Limkemann <stevelim@dgtech.com>
 * Copyright 1998 Steve Limkemann
 *
 * Wireshark - Network traffic analyzer
 * By Gerald Combs <gerald@wireshark.org>
 * Copyright 1998 Gerald Combs
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include "config.h"

#include <stdio.h>
#include <epan/packet.h>
#include <epan/prefs.h>
#include <epan/dissectors/packet-tcp.h>
#include "packet-bzflag.h"

/*
 * See
 *
 *     http://www.dgtech.com/bzflag/sys/www/docs/html/
 */

void proto_register_bzflag (void);
void proto_reg_handoff_bzflag (void);

static int proto_bzflag = -1;

static int hf_bzflag_string  = -1;
static int hf_bzfs_string    = -1;
static int hf_bzfs_version   = -1;
static int hf_len            = -1;
static int hf_player         = -1;
static int hf_src_player     = -1;
static int hf_dst_player     = -1;
static int hf_code           = -1;
static int hf_flag_abbrev    = -1;
static int hf_flag_quality   = -1;
static int hf_flag_shot      = -1;
static int hf_flag_name      = -1;
static int hf_flag_help      = -1;
static int hf_worldSize      = -1;
static int hf_gameType       = -1;
static int hf_SuperFlag      = -1;
static int hf_Jumping        = -1;
static int hf_Inertia        = -1;
static int hf_Ricochet       = -1;
static int hf_Shakable       = -1;
static int hf_Antidote       = -1;
static int hf_Handicap       = -1;
static int hf_NoTeamKills    = -1;
static int hf_playerSlot     = -1;
static int hf_maxShots       = -1;
static int hf_numFlags       = -1;
static int hf_linearAcc      = -1;
static int hf_angularAcc     = -1;
static int hf_shakeTimeout   = -1;
static int hf_shakeWins      = -1;
static int hf_hash           = -1;
static int hf_playerType     = -1;
static int hf_teamColor      = -1;
static int hf_callSign       = -1;
static int hf_motto          = -1;
static int hf_token          = -1;
static int hf_version        = -1;
static int hf_gameTime       = -1;
static int hf_messageType    = -1;
static int hf_messageContent = -1;
static int hf_count          = -1;
static int hf_varName        = -1;
static int hf_varValue       = -1;
static int hf_teamNumber     = -1;
static int hf_teamSize       = -1;
static int hf_teamWon        = -1;
static int hf_teamLost       = -1;
static int hf_flagIndex      = -1;
static int hf_flag_status    = -1;
static int hf_flag_endurance = -1;
static int hf_x              = -1;
static int hf_y              = -1;
static int hf_z              = -1;
static int hf_launch_x       = -1;
static int hf_launch_y       = -1;
static int hf_launch_z       = -1;
static int hf_landing_x      = -1;
static int hf_landing_y      = -1;
static int hf_landing_z      = -1;
static int hf_flightTime     = -1;
static int hf_flightEnd      = -1;
static int hf_flagSpeed      = -1;
static int hf_timeStamp      = -1;
static int hf_order          = -1;
static int hf_alive          = -1;
static int hf_paused         = -1;
static int hf_exploding      = -1;
static int hf_teleporting    = -1;
static int hf_flagActive     = -1;
static int hf_crossingWall   = -1;
static int hf_falling        = -1;
static int hf_onDriver       = -1;
static int hf_userInputs     = -1;
static int hf_jumpJets       = -1;
static int hf_playSound      = -1;
static int hf_x_short        = -1;
static int hf_y_short        = -1;
static int hf_z_short        = -1;
static int hf_vx_short       = -1;
static int hf_vy_short       = -1;
static int hf_vz_short       = -1;
static int hf_az_short       = -1;
static int hf_vaz_short      = -1;
static int hf_shotIndex      = -1;
static int hf_shotEndReason  = -1;
static int hf_victimPlayer   = -1;
static int hf_killerPlayer   = -1;
static int hf_killReason     = -1;
static int hf_playerCount    = -1;
static int hf_win            = -1;
static int hf_loss           = -1;
static int hf_tks            = -1;
static int hf_posX           = -1;
static int hf_posY           = -1;
static int hf_posZ           = -1;
static int hf_velX           = -1;
static int hf_velY           = -1;
static int hf_velZ           = -1;
static int hf_DT             = -1;
static int hf_lifeTime       = -1;
static int hf_pingSeqNo      = -1;
static int hf_isRegistered   = -1;
static int hf_isVerified     = -1;
static int hf_isAdmin        = -1;
static int hf_from_tp        = -1;
static int hf_to_tp          = -1;
static int hf_undecoded      = -1;

static gint ett_bzflag = -1;

static gint
decodePosition (tvbuff_t *tvb, gint offset, proto_tree *tree)
{
  proto_tree_add_item(tree, hf_x, tvb, offset, 4, ENC_BIG_ENDIAN);
  offset += 4;
  proto_tree_add_item(tree, hf_y, tvb, offset, 4, ENC_BIG_ENDIAN);
  offset += 4;
  proto_tree_add_item(tree, hf_z, tvb, offset, 4, ENC_BIG_ENDIAN);
  offset += 4;
  return offset;
}

static gint
decodeFlagInfo (tvbuff_t *tvb, gint offset, proto_tree *tree)
{
  proto_tree_add_item(tree, hf_flagIndex, tvb, offset, 2, ENC_BIG_ENDIAN);
  offset += 2;
  proto_tree_add_item(tree, hf_flag_abbrev, tvb, offset, 2, ENC_BIG_ENDIAN);
  offset += 2;
  proto_tree_add_item(tree, hf_flag_status, tvb, offset, 2, ENC_BIG_ENDIAN);
  offset += 2;
  proto_tree_add_item(tree, hf_flag_endurance, tvb, offset, 2, ENC_BIG_ENDIAN);
  offset += 2;
  proto_tree_add_item(tree, hf_player, tvb, offset, 1, ENC_BIG_ENDIAN);
  offset++;
  offset = decodePosition(tvb, offset, tree);
  proto_tree_add_item(tree, hf_launch_x, tvb, offset, 4, ENC_BIG_ENDIAN);
  offset += 4;
  proto_tree_add_item(tree, hf_launch_y, tvb, offset, 4, ENC_BIG_ENDIAN);
  offset += 4;
  proto_tree_add_item(tree, hf_launch_z, tvb, offset, 4, ENC_BIG_ENDIAN);
  offset += 4;
  proto_tree_add_item(tree, hf_landing_x, tvb, offset, 4, ENC_BIG_ENDIAN);
  offset += 4;
  proto_tree_add_item(tree, hf_landing_y, tvb, offset, 4, ENC_BIG_ENDIAN);
  offset += 4;
  proto_tree_add_item(tree, hf_landing_z, tvb, offset, 4, ENC_BIG_ENDIAN);
  offset += 4;
  proto_tree_add_item(tree, hf_flightTime, tvb, offset, 4, ENC_BIG_ENDIAN);
  offset += 4;
  proto_tree_add_item(tree, hf_flightEnd, tvb, offset, 4, ENC_BIG_ENDIAN);
  offset += 4;
  proto_tree_add_item(tree, hf_flagSpeed, tvb, offset, 4, ENC_BIG_ENDIAN);
  offset += 4;
  return offset;
}

static gint
decodeShotUpdate (tvbuff_t *tvb, gint offset, proto_tree *tree)
{
  proto_tree_add_item(tree, hf_player, tvb, offset, 1, ENC_BIG_ENDIAN);
  offset++;
  proto_tree_add_item(tree, hf_shotIndex, tvb, offset, 2, ENC_BIG_ENDIAN);
  offset += 2;
  proto_tree_add_item(tree, hf_posX, tvb, offset, 4, ENC_BIG_ENDIAN);
  offset += 4;
  proto_tree_add_item(tree, hf_posY, tvb, offset, 4, ENC_BIG_ENDIAN);
  offset += 4;
  proto_tree_add_item(tree, hf_posZ, tvb, offset, 4, ENC_BIG_ENDIAN);
  offset += 4;
  proto_tree_add_item(tree, hf_velX, tvb, offset, 4, ENC_BIG_ENDIAN);
  offset += 4;
  proto_tree_add_item(tree, hf_velY, tvb, offset, 4, ENC_BIG_ENDIAN);
  offset += 4;
  proto_tree_add_item(tree, hf_velZ, tvb, offset, 4, ENC_BIG_ENDIAN);
  offset += 4;
  proto_tree_add_item(tree, hf_DT, tvb, offset, 4, ENC_BIG_ENDIAN);
  offset += 4;
  proto_tree_add_item(tree, hf_teamColor, tvb, offset, 2, ENC_BIG_ENDIAN);
  offset += 2;
  return offset;
}

static void
decodePackedMessages (tvbuff_t *tvb, packet_info *pinfo, gint offset,
    proto_tree *tree)
{
  guint16 plen;
  guint16 code;
  plen  = tvb_get_ntohs(tvb, offset);
  proto_tree_add_item(tree, hf_len, tvb, offset, 2, ENC_BIG_ENDIAN);
  offset += 2;
  code  = tvb_get_ntohs(tvb, offset);
  proto_tree_add_item(tree, hf_code, tvb, offset, 2,
      ENC_BIG_ENDIAN);
  offset += 2;

  if (code == 0x4e66) {
    guint slen;

    col_set_str(pinfo->cinfo, COL_INFO, "NearFlag");
    offset = decodePosition(tvb, offset, tree);
    slen = tvb_get_ntohl(tvb, offset);
    proto_tree_add_item(tree, hf_flag_name, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4 + slen;
  } else if (code == 0x6163) {
    col_set_str(pinfo->cinfo, COL_INFO, "Accept");
    proto_tree_add_item(tree, hf_player, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;
  } else if (code == 0x616c) {
    col_set_str(pinfo->cinfo, COL_INFO, "Alive");
  } else if (code == 0x6170) {
    col_set_str(pinfo->cinfo, COL_INFO, "AddPlayer");
    proto_tree_add_item(tree, hf_player, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;
    proto_tree_add_item(tree, hf_playerType, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    proto_tree_add_item(tree, hf_teamColor, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    proto_tree_add_item(tree, hf_win, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    proto_tree_add_item(tree, hf_loss, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    proto_tree_add_item(tree, hf_tks, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    proto_tree_add_item(tree, hf_callSign, tvb, offset, 32, ENC_BIG_ENDIAN);
    offset += 32;
    proto_tree_add_item(tree, hf_motto, tvb, offset, 128, ENC_BIG_ENDIAN);
    offset += 128;
  } else if (code == 0x6366) {
    col_set_str(pinfo->cinfo, COL_INFO, "CaptureFlag");
    proto_tree_add_item(tree, hf_player, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;
    proto_tree_add_item(tree, hf_flagIndex, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    proto_tree_add_item(tree, hf_teamColor, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
  } else if (code == 0x6466) {
    col_set_str(pinfo->cinfo, COL_INFO, "DropFlag");
    if (plen == 12) {
      offset = decodePosition(tvb, offset, tree);
    } else {
      proto_tree_add_item(tree, hf_player, tvb, offset, 1, ENC_BIG_ENDIAN);
      offset++;
      offset = decodeFlagInfo(tvb, offset, tree);
    }
  } else if (code == 0x656e) {
    col_set_str(pinfo->cinfo, COL_INFO, "Enter");
    proto_tree_add_item(tree, hf_playerType, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    proto_tree_add_item(tree, hf_teamColor, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    proto_tree_add_item(tree, hf_callSign, tvb, offset, 32, ENC_BIG_ENDIAN);
    offset += 32;
    proto_tree_add_item(tree, hf_motto, tvb, offset, 128, ENC_BIG_ENDIAN);
    offset += 128;
    proto_tree_add_item(tree, hf_token, tvb, offset, 22, ENC_BIG_ENDIAN);
    offset += 22;
    proto_tree_add_item(tree, hf_version, tvb, offset, 60, ENC_BIG_ENDIAN);
    offset += 60;
    offset++;
  } else if (code == 0x6674) {
    guint slen;

    col_set_str(pinfo->cinfo, COL_INFO, "FlagType");
    proto_tree_add_item(tree, hf_flag_abbrev, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    proto_tree_add_item(tree, hf_flag_quality, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    proto_tree_add_item(tree, hf_flag_shot, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += 1;
    slen = tvb_get_ntohl(tvb, offset);
    proto_tree_add_item(tree, hf_flag_name, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4 + slen;
    slen = tvb_get_ntohl(tvb, offset);
    proto_tree_add_item(tree, hf_flag_help, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4 + slen;
  } else if (code == 0x6675) {
    guint16 count;

    col_set_str(pinfo->cinfo, COL_INFO, "FlagUpdate");
    count = tvb_get_ntohs(tvb, offset);
    proto_tree_add_item(tree, hf_count, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    for (; count > 0; count--) {
      offset = decodeFlagInfo(tvb, offset, tree);
    }
  } else if (code == 0x6766) {
    col_set_str(pinfo->cinfo, COL_INFO, "GrabFlag");
    if (plen == 2) {
      proto_tree_add_item(tree, hf_flagIndex, tvb, offset, 2, ENC_BIG_ENDIAN);
      offset += 2;
    } else {
      proto_tree_add_item(tree, hf_player, tvb, offset, 1, ENC_BIG_ENDIAN);
      offset++;
      offset = decodeFlagInfo(tvb, offset, tree);
    }
  } else if (code == 0x676d) {
    col_set_str(pinfo->cinfo, COL_INFO, "GMUpdate");
    offset = decodeShotUpdate(tvb, offset, tree);
    proto_tree_add_item(tree, hf_dst_player, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;
  } else if (code == 0x6773) {
    col_set_str(pinfo->cinfo, COL_INFO, "GameSettings");
    proto_tree_add_item(tree, hf_worldSize, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;
    proto_tree_add_item(tree, hf_gameType, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    proto_tree_add_item(tree, hf_SuperFlag,   tvb, offset, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_Jumping,     tvb, offset, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_Inertia,     tvb, offset, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_Ricochet,    tvb, offset, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_Shakable,    tvb, offset, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_Antidote,    tvb, offset, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_Handicap,    tvb, offset, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_NoTeamKills, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    proto_tree_add_item(tree, hf_playerSlot, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    proto_tree_add_item(tree, hf_maxShots, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    proto_tree_add_item(tree, hf_numFlags, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    proto_tree_add_item(tree, hf_linearAcc, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;
    proto_tree_add_item(tree, hf_angularAcc, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;
    proto_tree_add_item(tree, hf_shakeTimeout, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    proto_tree_add_item(tree, hf_shakeWins, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    // dummy zero Uint
    offset += 4;
  } else if (code == 0x6774) {
    col_set_str(pinfo->cinfo, COL_INFO, "GameTime");
    proto_tree_add_item(tree, hf_gameTime, tvb, offset, 8, ENC_BIG_ENDIAN);
    offset += 8;
  } else if (code == 0x6b6c) {
    col_set_str(pinfo->cinfo, COL_INFO, "Killed");
    if (plen == 8) {
      proto_tree_add_item(tree, hf_victimPlayer, tvb, offset, 1,
	  ENC_BIG_ENDIAN);
      offset++;
    }
    proto_tree_add_item(tree, hf_killerPlayer, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;
    proto_tree_add_item(tree, hf_killReason, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    proto_tree_add_item(tree, hf_shotIndex, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    proto_tree_add_item(tree, hf_flag_abbrev, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
  } else if (code == 0x6d67) {
    int msgSize = plen;

    col_set_str(pinfo->cinfo, COL_INFO, "Message");
    proto_tree_add_item(tree, hf_src_player, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;
    proto_tree_add_item(tree, hf_dst_player, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;
    proto_tree_add_item(tree, hf_messageType, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;
    msgSize -= 3;
    proto_tree_add_item(tree, hf_messageContent, tvb, offset, msgSize,
	ENC_BIG_ENDIAN);
    offset += msgSize;
  } else if (code == 0x6e66) {
    int i;

    col_set_str(pinfo->cinfo, COL_INFO, "NegotiateFlags");
    for (i = 0; i < plen / 2; i++) {
      proto_tree_add_item(tree, hf_flag_abbrev, tvb, offset, 2,
	  ENC_BIG_ENDIAN);
      offset += 2;
    }
  } else if (code == 0x6f66) {
    col_set_str(pinfo->cinfo, COL_INFO, "UDPLinkRequest");
    if (plen) {
      proto_tree_add_item(tree, hf_player, tvb, offset, 1, ENC_BIG_ENDIAN);
      offset += 1;
    }
  } else if (code == 0x6f67) {
    col_set_str(pinfo->cinfo, COL_INFO, "UDPLinkEstablished");
  } else if (code == 0x7062) {
    guint8 count;

    col_set_str(pinfo->cinfo, COL_INFO, "PlayerInfo");
    count = tvb_get_guint8(tvb, offset);
    proto_tree_add_item(tree, hf_playerCount, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;
    for (; count > 0; count--) {
      proto_tree_add_item(tree, hf_player, tvb, offset, 1, ENC_BIG_ENDIAN);
      offset++;
      proto_tree_add_item(tree, hf_isRegistered, tvb, offset, 1,
	  ENC_BIG_ENDIAN);
      proto_tree_add_item(tree, hf_isVerified, tvb, offset, 1, ENC_BIG_ENDIAN);
      proto_tree_add_item(tree, hf_isAdmin, tvb, offset, 1, ENC_BIG_ENDIAN);
      offset++;
    }
  } else if (code == 0x7069) {
    col_set_str(pinfo->cinfo, COL_INFO, "LagPing");
    proto_tree_add_item(tree, hf_pingSeqNo, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
  } else if (code == 0x7073) {
    col_set_str(pinfo->cinfo, COL_INFO, "PlayerUpdateSmall");
    proto_tree_add_item(tree, hf_timeStamp, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;
    proto_tree_add_item(tree, hf_player, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;
    proto_tree_add_item(tree, hf_order, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;
    proto_tree_add_item(tree, hf_alive,        tvb, offset, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_paused,       tvb, offset, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_exploding,    tvb, offset, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_teleporting,  tvb, offset, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_flagActive,   tvb, offset, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_crossingWall, tvb, offset, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_falling,      tvb, offset, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_onDriver,     tvb, offset, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_userInputs,   tvb, offset, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_jumpJets,     tvb, offset, 2, ENC_BIG_ENDIAN);
    proto_tree_add_item(tree, hf_playSound,    tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    proto_tree_add_item(tree, hf_x_short, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    proto_tree_add_item(tree, hf_y_short, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    proto_tree_add_item(tree, hf_z_short, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    proto_tree_add_item(tree, hf_vx_short, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    proto_tree_add_item(tree, hf_vy_short, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    proto_tree_add_item(tree, hf_vz_short, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    proto_tree_add_item(tree, hf_az_short, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    proto_tree_add_item(tree, hf_vaz_short, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
  } else if (code == 0x7270) {
    col_set_str(pinfo->cinfo, COL_INFO, "RemovePlayer");
    proto_tree_add_item(tree, hf_player, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;
  } else if (code == 0x7362) {
    col_set_str(pinfo->cinfo, COL_INFO, "ShotBegin");
    proto_tree_add_item(tree, hf_timeStamp, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;
    offset = decodeShotUpdate(tvb, offset, tree);
    proto_tree_add_item(tree, hf_flag_abbrev, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    proto_tree_add_item(tree, hf_lifeTime, tvb, offset, 4, ENC_BIG_ENDIAN);
    offset += 4;
  } else if (code == 0x7363) {
    guint8 count;

    col_set_str(pinfo->cinfo, COL_INFO, "Score");
    count = tvb_get_guint8(tvb, offset);
    proto_tree_add_item(tree, hf_playerCount, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;

    for (; count > 0; count--) {
      proto_tree_add_item(tree, hf_player, tvb, offset, 1, ENC_BIG_ENDIAN);
      offset++;
      proto_tree_add_item(tree, hf_win, tvb, offset, 2, ENC_BIG_ENDIAN);
      offset += 2;
      proto_tree_add_item(tree, hf_loss, tvb, offset, 2, ENC_BIG_ENDIAN);
      offset += 2;
      proto_tree_add_item(tree, hf_tks, tvb, offset, 2, ENC_BIG_ENDIAN);
      offset += 2;
    }
  } else if (code == 0x7365) {
    col_set_str(pinfo->cinfo, COL_INFO, "ShotEnd");
    proto_tree_add_item(tree, hf_player, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;
    proto_tree_add_item(tree, hf_shotIndex, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    proto_tree_add_item(tree, hf_shotEndReason, tvb, offset, 2,
	ENC_BIG_ENDIAN);
    offset += 2;
  } else if (code == 0x7376) {
    int    remaining;
    guint8 stringLength;

    remaining = plen;
    col_set_str(pinfo->cinfo, COL_INFO, "SetVar");
    proto_tree_add_item(tree, hf_count, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset    += 2;
    remaining -= 2;
    while (remaining > 0) {
      stringLength  = tvb_get_guint8(tvb, offset);
      proto_tree_add_item(tree, hf_varName, tvb, offset, 1, ENC_BIG_ENDIAN);
      offset    += 1 + stringLength;
      remaining -= 1 + stringLength;
      stringLength  = tvb_get_guint8(tvb, offset);
      proto_tree_add_item(tree, hf_varValue, tvb, offset, 1, ENC_BIG_ENDIAN);
      offset    += 1 + stringLength;
      remaining -= 1 + stringLength;
    }
  } else if (code == 0x7466) {
    col_set_str(pinfo->cinfo, COL_INFO, "TransferFlag");
    proto_tree_add_item(tree, hf_src_player, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;
    proto_tree_add_item(tree, hf_dst_player, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;
    if (plen > 2) {
      offset = decodeFlagInfo(tvb, offset, tree);
    }
  } else if (code == 0x7470) {
    col_set_str(pinfo->cinfo, COL_INFO, "Teleport");
    proto_tree_add_item(tree, hf_player, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;
    proto_tree_add_item(tree, hf_from_tp, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
    proto_tree_add_item(tree, hf_to_tp, tvb, offset, 2, ENC_BIG_ENDIAN);
    offset += 2;
  } else if (code == 0x7475) {
    guint8 teamNo;
    guint8 i;

    col_set_str(pinfo->cinfo, COL_INFO, "TeamUpdate");
    teamNo = tvb_get_guint8(tvb, offset);
    proto_tree_add_item(tree, hf_teamNumber, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset++;
    for (i = 0; i < teamNo; i++) {
      proto_tree_add_item(tree, hf_teamColor, tvb, offset, 2, ENC_BIG_ENDIAN);
      offset += 2;
      proto_tree_add_item(tree, hf_teamSize, tvb, offset, 2, ENC_BIG_ENDIAN);
      offset += 2;
      proto_tree_add_item(tree, hf_teamWon, tvb, offset, 2, ENC_BIG_ENDIAN);
      offset += 2;
      proto_tree_add_item(tree, hf_teamLost, tvb, offset, 2, ENC_BIG_ENDIAN);
      offset += 2;
    }
  } else if (code == 0x7768) {
    col_set_str(pinfo->cinfo, COL_INFO, "WantWHash");
    if (plen) {
      proto_tree_add_item(tree, hf_hash, tvb, offset, plen, ENC_BIG_ENDIAN);
      offset += plen;
    }
  } else if (code == 0x7773) {
    col_set_str(pinfo->cinfo, COL_INFO, "WantSettings");
  } else {
    col_set_str(pinfo->cinfo, COL_INFO, "Not Decoded");
    proto_tree_add_item(tree, hf_undecoded, tvb, offset, 1, ENC_BIG_ENDIAN);
    offset += plen;
  }
}

static void
dissect_bzflag_common(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree)
{
  proto_tree *bzflag_tree;
  proto_item *ti;
  gint        offset = 0;

  col_set_str(pinfo->cinfo, COL_PROTOCOL, "BZflag");
  ti = proto_tree_add_item(tree, proto_bzflag, tvb, 0, -1, ENC_NA);
  bzflag_tree = proto_item_add_subtree(ti, ett_bzflag);
  decodePackedMessages(tvb, pinfo, offset, bzflag_tree);
}

static int
dissect_bzflag_tcp_pdu(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
    void* data _U_)
{
  dissect_bzflag_common(tvb, pinfo, tree);
  return tvb_reported_length(tvb);
}

static guint
get_bzflag_pdu_len(packet_info *pinfo _U_, tvbuff_t *tvb, int offset,
    void *data _U_)
{
  guint16 plen;

  /*
   *    * Get the length of the BZFlag packet.
   *       */
  plen = tvb_get_ntohs(tvb, offset) + 4;

  return plen;
}

static int
dissect_tcp_bzflag (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
    void *data _U_)
{
  proto_tree      *bzflag_tree;
  proto_item      *ti;
  gint            len;
  gint            offset = 0;

  if (tree == NULL)
    return -1;

  len = tvb_reported_length(tvb);
  if (len == 10) {
    char str[6];
    const char BZFlag_String[] ="BZFLAG";

    tvb_memcpy(tvb, str, offset, 6);
    if (!memcmp(str, BZFlag_String, 6)) {
      col_set_str(pinfo->cinfo, COL_PROTOCOL, "BZflag");
      ti = proto_tree_add_item(tree, proto_bzflag, tvb, 0, -1, ENC_NA);
      bzflag_tree = proto_item_add_subtree(ti, ett_bzflag);
      col_set_str(pinfo->cinfo, COL_INFO, "BZFLAG Magic");
      proto_tree_add_item(bzflag_tree, hf_bzflag_string, tvb, offset, 10, ENC_NA);
      return len;
    }
  } else if (len == 9) {
    char str[4];
    const char BZFS_String[] ="BZFS";

    tvb_memcpy(tvb, str, offset, 4);
    if (!memcmp(str, BZFS_String, 4)) {
      col_set_str(pinfo->cinfo, COL_PROTOCOL, "BZflag");
      ti = proto_tree_add_item(tree, proto_bzflag, tvb, 0, -1, ENC_NA);
      bzflag_tree = proto_item_add_subtree(ti, ett_bzflag);
      col_set_str(pinfo->cinfo, COL_INFO, "BZFS Version");
      proto_tree_add_item(bzflag_tree, hf_bzfs_string,  tvb, offset, 4, ENC_NA);
      offset += 4;
      proto_tree_add_item(bzflag_tree, hf_bzfs_version, tvb, offset, 4, ENC_NA);
      offset += 4;
      proto_tree_add_item(bzflag_tree, hf_player, tvb, offset, 1, ENC_NA);
      return len;
    }
  }
  tcp_dissect_pdus(tvb, pinfo, tree, TRUE, 2, get_bzflag_pdu_len,
      dissect_bzflag_tcp_pdu, data);
  return tvb_reported_length(tvb);
}

static int
dissect_udp_bzflag (tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree,
    void *data _U_)
{
  gint len;

  len = tvb_reported_length(tvb);
  dissect_bzflag_common(tvb, pinfo, tree);
  return len;
}

void
gameTime (gchar *label, guint64 item)
{
  time_t       timep;
  unsigned int micro;
  struct tm   *bt;
  char   timeLabel[ITEM_LABEL_LENGTH];

  timep = item / 1000000;
  micro = item % 1000000;
  bt    = gmtime(&timep);

  strftime(timeLabel, ITEM_LABEL_LENGTH, "%c", bt);
  snprintf(label, ITEM_LABEL_LENGTH, "%s %i usec", timeLabel, micro);
}

void
proto_register_bzflag (void)
{
  static const value_string teamColor[] = {
    {-2, "AutomaticTeam"},
    {-1, "NoTeam"},
    {0,  "RogueTeam"},
    {1,  "RedTeam"},
    {2,  "GreenTeam"},
    {3,  "BlueTeam"},
    {4,  "PurpleTeam"},
    {5,  "ObserverTeam"},
    {6,  "RabbitTeam"},
    {7,  "HunterTeam"},
    {0,  NULL}
  };

  static const value_string shotEndReason[] = {
    {0x0000, "GotKilledMsg"},
    {0x0001, "GotShot"},
    {0x0002, "GotRunOver"},
    {0x0003, "GotCaptured"},
    {0x0004, "GenocideEffect"},
    {0x0005, "SelfDestruct"},
    {0x0006, "WaterDeath"},
    {0x0007, "LastReason"},
    {0x0008, "DeathTouch/PhysicsDriverDeath"},
    {0,      NULL}
  };

  static const value_string messageType[] = {
    {0x0000, "ChatMessage"},
    {0x0001, "ActionMessage"},
    {0,      NULL}
  };

  static const value_string playerType[] = {
    {0x0000, "TankPlayer"},
    {0x0001, "ComputerPlayer"},
    {0,      NULL}
  };

  static const value_string flagEndurance[] = {
    {0x0000, "FlagNormal"},
    {0x0001, "FlagUnstable"},
    {0x0002, "FlagSticky"},
    {0,      NULL}
  };

  static const value_string flagStatus[] = {
    {0x0000, "FlagNoExist"},
    {0x0001, "FlagOnGround"},
    {0x0002, "FlagOnTank"},
    {0x0003, "FlagInAir"},
    {0x0004, "FlagComing"},
    {0x0005, "FlagGoing"},
    {0,      NULL}
  };

  static const value_string gameType[] = {
    {0x0000, "TeamFFA"},
    {0x0001, "ClassicCTF"},
    {0x0002, "OpenFFA"},
    {0x0003, "RabbitChase"},
    {0,      NULL}
  };

  static const range_string player[] = {
    {0x00, 0xfa, "NormalPlayer"},
    {0xfb, 0xfb, "FirstTeam"},
    {0xfc, 0xfc, "AdminPlayers"},
    {0xfd, 0xfd, "ServerPlayer"},
    {0xfe, 0xfe, "AllPlayers"},
    {0xff, 0xff, "NoPlayer"},
    {0,    0,    NULL}
  };

  static const value_string codeName[] = {
    {0x6163, "MsgAccept"},
    {0x616c, "MsgAlive"},
    {0x6170, "MsgAddPlayer"},
    {0x6366, "MsgCaptureFlag"}, // 1482
    {0x6466, "MsgDropFlag"},
    {0x656e, "MsgEnter"},
    {0x6674, "MsgFlagType"},
    {0x6675, "MsgFlagUpdate"},
    {0x6766, "MsgGrabFlag"},
    {0x676d, "MsgGMUpdate"},
    {0x6773, "MsgGameSettings"},
    {0x6774, "MsgGameTime"},
    {0x6b6c, "MsgKilled"},
    {0x6d67, "MsgMessage"},
    {0x6e66, "MsgNegotiateFlags"},
    {0x6f66, "MsgUDPLinkRequest"},
    {0x6f67, "MsgUDPLinkEstablished"},
    {0x7062, "MsgPlayerInfo"},
    {0x7069, "MsgLagPing"},
    {0x7073, "MsgPlayerUpdateSmall"},
    {0x7270, "MsgRemovePlayer"},
    {0x7362, "MsgShotBegin"},
    {0x7363, "MsgScore"},
    {0x7365, "MsgShotEnd"},
    {0x7376, "MsgSetVar"},
    {0x7466, "MsgTransferFlag"},
    {0x7470, "MsgTeleport"},
    {0x7475, "MsgTeamUpdate"},
    {0x7768, "MsgWantWHash"},
    {0x7773, "MsgWantSettings"},
    {0,      NULL}
  };

  static const true_false_string good_bad = {
    "Bad Flag",
    "Good Flag"
  };

  static const true_false_string specialShot = {
    "Special Shot",
    "Normal Shot"
  };

  static hf_register_info hf[] = {
    {&hf_bzflag_string,
      {"BZFLAG String", "bzflag.bzflagString", FT_STRING, STR_ASCII, NULL, 0x0,
	NULL, HFILL}},
    {&hf_bzfs_string,
      {"BZFS String", "bzflag.bzfsString", FT_STRING, STR_ASCII, NULL, 0x0,
	NULL, HFILL}},
    {&hf_bzfs_version,
      {"BZFS Version", "bzflag.bzfsVersion", FT_STRING, STR_ASCII, NULL, 0x0,
	NULL, HFILL}},
    {&hf_len,
      {"Len", "bzflag.len", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL}},
    {&hf_code,
      {"Code", "bzflag.code", FT_UINT16, BASE_HEX, codeName, 0x0, NULL,
	HFILL}},
    {&hf_player,
      {"PlayerId", "bzflag.player", FT_UINT8, BASE_DEC | BASE_RANGE_STRING,
	RVALS(player), 0x0, NULL, HFILL}},
    {&hf_src_player,
      {"SrcPlayerId", "bzflag.src.player", FT_UINT8,
	BASE_DEC | BASE_RANGE_STRING, RVALS(player), 0x0, NULL, HFILL}},
    {&hf_dst_player,
      {"DstPlayerId", "bzflag.dst.player", FT_UINT8,
	BASE_DEC | BASE_RANGE_STRING, RVALS(player), 0x0, NULL, HFILL}},
    {&hf_flag_abbrev,
      {"Flag Abbrev", "bzflag.flag.abbrev", FT_STRING, STR_ASCII, NULL, 0x0,
	NULL, HFILL}},
    {&hf_flag_quality,
      {"Flag Quality", "bzflag.flag.quality", FT_BOOLEAN, BASE_NONE,
	TFS(&good_bad), 0x0, NULL, HFILL}},
    {&hf_flag_shot,
      {"Flag Shot", "bzflag.flag.shot", FT_BOOLEAN, BASE_NONE,
	TFS(&specialShot), 0x0, NULL, HFILL}},
    {&hf_flag_name,
      {"Flag Name", "bzflag.flag.name", FT_UINT_STRING, STR_ASCII, NULL, 0x0,
	NULL, HFILL}},
    {&hf_flag_help,
      {"Flag Help", "bzflag.flag.help", FT_UINT_STRING, STR_ASCII, NULL, 0x0,
	NULL, HFILL}},
    {&hf_worldSize,
      {"World Size", "bzflag.world.size", FT_FLOAT, BASE_NONE, NULL, 0x0, NULL,
	HFILL}},
    {&hf_gameType,
      {"Game Type", "bzflag.world.gameType", FT_UINT16, BASE_DEC, gameType,
	0x0, NULL, HFILL}},
    {&hf_SuperFlag,
      {"SuperFlag", "bzflag.world.superflag", FT_BOOLEAN, 16, NULL, 0x0002,
	NULL, HFILL}},
    {&hf_Jumping,
      {"Jumping", "bzflag.world.jumping", FT_BOOLEAN, 16, NULL, 0x0008, NULL,
	HFILL}},
    {&hf_Inertia,
      {"Inertia", "bzflag.world.inertia", FT_BOOLEAN, 16, NULL, 0x0010, NULL,
	HFILL}},
    {&hf_Ricochet,
      {"Ricochet", "bzflag.world.ricochet", FT_BOOLEAN, 16, NULL, 0x0020, NULL,
	HFILL}},
    {&hf_Shakable,
      {"Shakable", "bzflag.world.shakable", FT_BOOLEAN, 16, NULL, 0x0040, NULL,
	HFILL}},
    {&hf_Antidote,
      {"Antidote", "bzflag.world.antidote", FT_BOOLEAN, 16, NULL, 0x0080, NULL,
	HFILL}},
    {&hf_Handicap,
      {"Handicap", "bzflag.world.handicap", FT_BOOLEAN, 16, NULL, 0x0100, NULL,
	HFILL}},
    {&hf_NoTeamKills,
      {"NoTeamKill", "bzflag.world.noteamkills", FT_BOOLEAN, 16, NULL, 0x0400,
	NULL, HFILL}},
    {&hf_playerSlot,
      {"PlayerSlot", "bzflag.world.playerSlot", FT_UINT16, BASE_DEC, NULL, 0x0,
	NULL, HFILL}},
    {&hf_maxShots,
      {"MaxShots", "bzflag.world.maxShots", FT_UINT16, BASE_DEC, NULL, 0x0,
	NULL, HFILL}},
    {&hf_numFlags,
      {"NumFlags", "bzflag.world.numFlags", FT_UINT16, BASE_DEC, NULL, 0x0,
	NULL, HFILL}},
    {&hf_linearAcc,
      {"LinearAcc", "bzflag.world.linAcc", FT_FLOAT, BASE_NONE, NULL, 0x0,
	NULL, HFILL}},
    {&hf_angularAcc,
      {"AngularAcc", "bzflag.world.angAcc", FT_FLOAT, BASE_NONE, NULL, 0x0,
	NULL, HFILL}},
    {&hf_shakeTimeout,
      {"ShakeTimeout", "bzflag.world.shakeTimeout", FT_UINT16, BASE_DEC, NULL,
	0x0, NULL, HFILL}},
    {&hf_shakeWins,
      {"ShakeWins", "bzflag.world.shakeWins", FT_UINT16, BASE_DEC, NULL, 0x0,
	NULL, HFILL}},
    {&hf_hash,
      {"WorldHash", "bzflag.world.hash", FT_STRING, STR_ASCII, NULL, 0x0, NULL,
	HFILL}},
    {&hf_playerType,
      {"PlayerType", "bzflag.player.type", FT_UINT16, BASE_DEC, playerType,
	0x0, NULL, HFILL}},
    {&hf_teamColor,
      {"TeamColor", "bzflag.teamColor", FT_INT16, BASE_DEC, teamColor, 0x0,
	NULL, HFILL}},
    {&hf_callSign,
      {"CallSign", "bzflag.player.callsign", FT_STRING, STR_ASCII, NULL, 0x0,
	NULL, HFILL}},
    {&hf_motto,
      {"Motto", "bzflag.player.motto", FT_STRING, STR_ASCII, NULL, 0x0, NULL,
	HFILL}},
    {&hf_token,
      {"Token", "bzflag.player.token", FT_STRING, STR_ASCII, NULL, 0x0, NULL,
	HFILL}},
    {&hf_version,
      {"Version", "bzflag.player.version", FT_STRING, STR_ASCII, NULL, 0x0,
	NULL, HFILL}},
    {&hf_gameTime,
      {"GameTime", "bzflag.server.time", FT_UINT64, BASE_CUSTOM,
	CF_FUNC(gameTime), 0x0, NULL, HFILL}},
    {&hf_messageType,
      {"MessageType", "bzflag.message.type", FT_UINT8, BASE_DEC, messageType,
	0x0, NULL, HFILL}},
    {&hf_messageContent,
      {"MessageContent", "bzflag.message.content", FT_STRING, STR_ASCII, NULL,
	0x0, NULL, HFILL}},
    {&hf_count,
      {"Count", "bzflag.count", FT_UINT16, BASE_DEC, NULL, 0x0, NULL, HFILL}},
    {&hf_varName,
      {"VarName", "bzflag.var.name", FT_UINT_STRING, STR_ASCII, NULL, 0x0,
	NULL, HFILL}},
    {&hf_varValue,
      {"VarValue", "bzflag.var.value", FT_UINT_STRING, STR_ASCII, NULL, 0x0,
	NULL, HFILL}},
    {&hf_teamNumber,
      {"NumberOfTeams", "bzflag.team.number", FT_UINT8, BASE_DEC, NULL, 0x0,
	NULL, HFILL}},
    {&hf_teamSize,
      {"SizeOfTeam", "bzflag.team.size", FT_UINT16, BASE_DEC, NULL, 0x0, NULL,
	HFILL}},
    {&hf_teamWon,
      {"TeamWon", "bzflag.team.won", FT_UINT16, BASE_DEC, NULL, 0x0, NULL,
	HFILL}},
    {&hf_teamLost,
      {"TeamLost", "bzflag.team.lost", FT_UINT16, BASE_DEC, NULL, 0x0, NULL,
	HFILL}},
    {&hf_flagIndex,
      {"FlagIndex", "bzflag.flag.index", FT_UINT16, BASE_DEC, NULL, 0x0, NULL,
	HFILL}},
    {&hf_flag_status,
      {"Flag Status", "bzflag.flag.status", FT_UINT16, BASE_DEC, flagStatus,
	0x0, NULL, HFILL}},
    {&hf_flag_endurance,
      {"Flag Endurance", "bzflag.flag.endurance", FT_UINT16, BASE_DEC,
	flagEndurance, 0x0, NULL, HFILL}},
    {&hf_x,
      {"X Position", "bzflag.x", FT_FLOAT, BASE_NONE, NULL, 0x0, NULL, HFILL}},
    {&hf_y,
      {"Y Position", "bzflag.y", FT_FLOAT, BASE_NONE, NULL, 0x0, NULL, HFILL}},
    {&hf_z,
      {"Z Position", "bzflag.z", FT_FLOAT, BASE_NONE, NULL, 0x0, NULL, HFILL}},
    {&hf_launch_x,
      {"X Launch Position", "bzflag.launch.x", FT_FLOAT, BASE_NONE, NULL, 0x0,
	NULL, HFILL}},
    {&hf_launch_y,
      {"Y Launch Position", "bzflag.launch.y", FT_FLOAT, BASE_NONE, NULL, 0x0,
	NULL, HFILL}},
    {&hf_launch_z,
      {"Z Landing Position", "bzflag.land.z", FT_FLOAT, BASE_NONE, NULL, 0x0,
	NULL, HFILL}},
    {&hf_landing_x,
      {"X Landing Position", "bzflag.land.x", FT_FLOAT, BASE_NONE, NULL, 0x0,
	NULL, HFILL}},
    {&hf_landing_y,
      {"Y Landing Position", "bzflag.land.y", FT_FLOAT, BASE_NONE, NULL, 0x0,
	NULL, HFILL}},
    {&hf_landing_z,
      {"Z Launch Position", "bzflag.launch.z", FT_FLOAT, BASE_NONE, NULL, 0x0,
	NULL, HFILL}},
    {&hf_flightTime,
      {"Flight Time", "bzflag.flag.flight.time", FT_FLOAT, BASE_NONE, NULL,
	0x0, NULL, HFILL}},
    {&hf_flightEnd,
      {"Flight End", "bzflag.flag.flight.end", FT_FLOAT, BASE_NONE, NULL, 0x0,
	NULL, HFILL}},
    {&hf_flagSpeed,
      {"Flag Speed", "bzflag.flag.flight.speed", FT_FLOAT, BASE_NONE, NULL,
	0x0, NULL, HFILL}},
    {&hf_timeStamp,
      {"Time Stamp", "bzflag.timestamp", FT_FLOAT, BASE_NONE, NULL, 0x0, NULL,
	HFILL}},
    {&hf_order,
      {"Order", "bzflag.player.order", FT_UINT32, BASE_DEC, NULL, 0x0, NULL,
	HFILL}},
    {&hf_alive,
      {"Alive", "bzflag.player.alive", FT_BOOLEAN, 16, NULL, 0x0001, NULL,
	HFILL}},
    {&hf_paused,
      {"Paused", "bzflag.player.paused", FT_BOOLEAN, 16, NULL, 0x0002, NULL,
	HFILL}},
    {&hf_exploding,
      {"Exploding", "bzflag.player.exploding", FT_BOOLEAN, 16, NULL, 0x0004,
	NULL, HFILL}},
    {&hf_teleporting,
      {"Teleporting", "bzflag.player.teleporting", FT_BOOLEAN, 16, NULL,
	0x0008, NULL, HFILL}},
    {&hf_flagActive,
      {"Flag Active", "bzflag.player.flag.active", FT_BOOLEAN, 16, NULL,
	0x0010, NULL, HFILL}},
    {&hf_crossingWall,
      {"Crossing Wall", "bzflag.player.crossingWall", FT_BOOLEAN, 16, NULL,
	0x0020, NULL, HFILL}},
    {&hf_falling,
      {"Falling", "bzflag.player.falling", FT_BOOLEAN, 16, NULL, 0x0040, NULL,
	HFILL}},
    {&hf_onDriver,
      {"On Driver", "bzflag.player.onDriver", FT_BOOLEAN, 16, NULL, 0x0080,
	NULL, HFILL}},
    {&hf_userInputs,
      {"User Inputs", "bzflag.player.userInputs", FT_BOOLEAN, 16, NULL, 0x0100,
	NULL, HFILL}},
    {&hf_jumpJets,
      {"Jump Jets", "bzflag.player.jumpJets", FT_BOOLEAN, 16, NULL, 0x0200,
	NULL, HFILL}},
    {&hf_playSound,
      {"Play Sound", "bzflag.player.playSound", FT_BOOLEAN, 16, NULL, 0x0400,
	NULL, HFILL}},
    {&hf_x_short,
      {"X Short", "bzflag.player.xS", FT_INT16, BASE_DEC, NULL, 0x0, NULL,
	HFILL}},
    {&hf_y_short,
      {"Y Short", "bzflag.player.yS", FT_INT16, BASE_DEC, NULL, 0x0, NULL,
	HFILL}},
    {&hf_z_short,
      {"Z Short", "bzflag.player.zS", FT_INT16, BASE_DEC, NULL, 0x0, NULL,
	HFILL}},
    {&hf_vx_short,
      {"VX Short", "bzflag.player.vxS", FT_INT16, BASE_DEC, NULL, 0x0, NULL,
	HFILL}},
    {&hf_vy_short,
      {"VY Short", "bzflag.player.vyS", FT_INT16, BASE_DEC, NULL, 0x0, NULL,
	HFILL}},
    {&hf_vz_short,
      {"VZ Short", "bzflag.player.vzS", FT_INT16, BASE_DEC, NULL, 0x0, NULL,
	HFILL}},
    {&hf_az_short,
      {"AZ Short", "bzflag.player.azS", FT_INT16, BASE_DEC, NULL, 0x0, NULL,
	HFILL}},
    {&hf_vaz_short,
      {"VAZ Short", "bzflag.player.vazS", FT_INT16, BASE_DEC, NULL, 0x0, NULL,
	HFILL}},
    {&hf_shotIndex,
      {"Shot Index", "bzflag.shot.index", FT_INT16, BASE_DEC, NULL, 0x0, NULL,
	HFILL}},
    {&hf_shotEndReason,
      {"ShotEnd Reason", "bzflag.shot.reason", FT_INT16, BASE_DEC,
	shotEndReason, 0x0, NULL, HFILL}},
    {&hf_victimPlayer,
      {"Victim", "bzflag.kill.victim", FT_INT8,
	BASE_DEC | BASE_RANGE_STRING, RVALS(player), 0x0, NULL, HFILL}},
    {&hf_killerPlayer,
      {"Killer", "bzflag.kill.killer", FT_INT8,
	BASE_DEC | BASE_RANGE_STRING, RVALS(player), 0x0, NULL, HFILL}},
    {&hf_killReason,
      {"Kill Reason", "bzflag.kill.reason", FT_INT16, BASE_DEC, shotEndReason,
	0x0, NULL, HFILL}},
    {&hf_playerCount,
      {"Count", "bzflag.players.count", FT_INT8, BASE_DEC, NULL, 0x0,
	NULL, HFILL}},
    {&hf_win,
      {"Win", "bzflag.player.win", FT_INT16, BASE_DEC, NULL, 0x0,
	NULL, HFILL}},
    {&hf_loss,
      {"Loss", "bzflag.player.loss", FT_INT16, BASE_DEC, NULL, 0x0,
	NULL, HFILL}},
    {&hf_tks,
      {"Team Kills", "bzflag.player.tks", FT_INT16, BASE_DEC, NULL, 0x0,
	NULL, HFILL}},
    {&hf_posX,
      {"Position X", "bzflag.pos.x", FT_FLOAT, BASE_NONE, NULL, 0x0, NULL,
	HFILL}},
    {&hf_posY,
      {"Position Y", "bzflag.pos.y", FT_FLOAT, BASE_NONE, NULL, 0x0, NULL,
	HFILL}},
    {&hf_posZ,
      {"Position Z", "bzflag.pos.z", FT_FLOAT, BASE_NONE, NULL, 0x0, NULL,
	HFILL}},
    {&hf_velX,
      {"Velocity X", "bzflag.vel.x", FT_FLOAT, BASE_NONE, NULL, 0x0, NULL,
	HFILL}},
    {&hf_velY,
      {"Velocity Y", "bzflag.vel.y", FT_FLOAT, BASE_NONE, NULL, 0x0, NULL,
	HFILL}},
    {&hf_velZ,
      {"Velocity Z", "bzflag.vel.z", FT_FLOAT, BASE_NONE, NULL, 0x0, NULL,
	HFILL}},
    {&hf_DT,
      {"Delta Time", "bzflag.deltaTime", FT_FLOAT, BASE_NONE, NULL, 0x0, NULL,
	HFILL}},
    {&hf_lifeTime,
      {"Life Time", "bzflag.lifeTime", FT_FLOAT, BASE_NONE, NULL, 0x0, NULL,
	HFILL}},
    {&hf_pingSeqNo,
      {"Ping Sequence Number", "bzflag.pingSeqNo", FT_UINT16, BASE_DEC, NULL,
	0x0, NULL, HFILL}},
    {&hf_isRegistered,
      {"Player Registered", "bzflag.player.registered", FT_BOOLEAN, 8, NULL,
	0x01, NULL, HFILL}},
    {&hf_isVerified,
      {"Player Verified", "bzflag.player.verified", FT_BOOLEAN, 8, NULL, 0x02,
	NULL, HFILL}},
    {&hf_isAdmin,
      {"Player Admin", "bzflag.player.admin", FT_BOOLEAN, 8, NULL, 0x04,
	NULL, HFILL}},
    {&hf_from_tp,
      {"From Teleporter", "bzflag.teleport.from", FT_UINT16, BASE_DEC, NULL,
	0x0, NULL, HFILL}},
    {&hf_to_tp,
      {"To Teleporter", "bzflag.teleport.to", FT_UINT16, BASE_DEC, NULL, 0x0,
	NULL, HFILL}},
    {&hf_undecoded,
      {"Undecoded", "bzflag.undecoded", FT_BOOLEAN, BASE_NONE, NULL, 0x0,
	NULL, HFILL}},
  };

  static gint *ett[] = {
    &ett_bzflag,
  };

  proto_bzflag = proto_register_protocol("BZflag Protocol",
      "BZflag",
      "bzflag");
  proto_register_field_array(proto_bzflag, hf, array_length(hf));
  proto_register_subtree_array(ett, array_length(ett));
}

void
proto_reg_handoff_bzflag (void)
{
  dissector_handle_t bzflag_udp_handle;
  dissector_handle_t bzflag_tcp_handle;

  bzflag_tcp_handle = new_create_dissector_handle(dissect_tcp_bzflag,
      proto_bzflag);
  bzflag_udp_handle = new_create_dissector_handle(dissect_udp_bzflag,
      proto_bzflag);
  dissector_add_uint("tcp.port", 4202, bzflag_tcp_handle);
  dissector_add_uint("udp.port", 4202, bzflag_udp_handle);
}
