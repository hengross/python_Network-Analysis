import os
import sqlite3


class DB:
    def __init__(self, DataBaseName):
        self.dbName = DataBaseName + ".db"

    def createDB(self):
        # check if DB exsist -> if so delete
        if(os.path.isfile(self.dbName)):
            os.remove(self.dbName)
        # connect to DB
        connection = sqlite3.connect(self.dbName)

        cursor = connection.cursor()

        # create Usgae table
        create_usage_table = """
        CREATE TABLE usage (
        MAC VARCHAR(17) PRIMARY KEY,
        sent DOUBLE,
        retransmit DOUBLE);"""
        cursor.execute(create_usage_table)

        # create Session table
        create_session_table = """
        CREATE TABLE session (
        MAC_SRC VARCHAR(17),
        MAC_DST VARCHAR(17),
        channel INT,
        packets DOUBLE,
        retransmit DOUBLE,
        PRIMARY KEY (MAC_SRC, MAC_DST, channel));"""
        cursor.execute(create_session_table)

        # create Routers table
        create_routers_table = """
        CREATE TABLE routers (
        ROUTER VARCHAR(17),
        CHANNEL INT,
        SSID VARCHAR(256),
        CONNECTIONS INTEGER,
        PRIMARY KEY (ROUTER, CHANNEL));"""
        cursor.execute(create_routers_table)

        # create Routers Connections table
        create_routers_client_table = """
                CREATE TABLE routers_client (
                ROUTER VARCHAR(17),
                CLIENT VARCHAR(17),
                PRIMARY KEY (ROUTER, CLIENT));"""
        cursor.execute(create_routers_client_table)

        # commit commands and close connection to DB
        connection.commit()
        connection.close()
        print("finish creating DB " + self.dbName)

    def insertToTable(self, tableName, data):

        if (tableName == "usage"):
            self.__insertToUsageTable(data)
        elif (tableName == "session"):
            self.__insertToSessionTable(data)
        elif (tableName == "routers"):
            self.__insertToRoutersTable(data)
        elif (tableName == "routers_client"):
            self.__insertToRoutersClientTable(data)
        else:
            print("ERROR: No such table - " + tableName)

    def __insertToUsageTable(self, data):

        # connect to db
        connection = sqlite3.connect(self.dbName)
        cursor = connection.cursor()

        for pkts in data.iterkeys():
            format_str = """INSERT INTO usage (MAC, sent, retransmit)
            VALUES ("{mac}", "{sent}", "{retransmit}");"""

            sql_command = format_str.format(mac=pkts, sent=data.get(pkts)[0], retransmit=data.get(pkts)[1])
            cursor.execute(sql_command)

        connection.commit()
        connection.close()

        print("Done insert to usage table")

    def __insertToSessionTable(self, data):
        # connect to db
        connection = sqlite3.connect(self.dbName)
        cursor = connection.cursor()

        broadcastNum = 0
        mac_dst = ""
        for pkts in data.iterkeys():
            format_str = """INSERT INTO session (MAC_SRC, MAC_DST ,packets, retransmit, channel)
                    VALUES ("{mac_src}", "{mac_dst}", "{packets}", "{retransmit}", "{channel}");"""
            # if (pkts[18:35] == "ff:ff:ff:ff:ff:ff"):
            #     sql_command = format_str.format(mac_src=pkts[:17], mac_dst = broadcastNum, packets=data.get(pkts)[0],
            #                                     retransmit=data.get(pkts)[1], channel=pkts[36:])
            #     broadcastNum += 1
            # else:
            sql_command = format_str.format(mac_src=pkts[:17], mac_dst=pkts[18:35], packets=data.get(pkts)[0],
                                            retransmit=data.get(pkts)[1], channel=pkts[36:])

            cursor.execute(sql_command)

        connection.commit()
        connection.close()

        print("Done insert to session table")

    def __insertToRoutersTable(self, data):
        # connect to db
        connection = sqlite3.connect(self.dbName)
        cursor = connection.cursor()

        for pkts in data.iterkeys():
            format_str = """INSERT INTO routers (ROUTER, CHANNEL ,SSID, CONNECTIONS)
                            VALUES ("{router}", "{channel}", "{ssid}", "{connections}");"""

            sql_command = format_str.format(router=pkts[:17], channel=pkts[18:], ssid=data.get(pkts)[0],
                                            connections=data.get(pkts)[1])
            cursor.execute(sql_command)

        connection.commit()
        connection.close()

        print("Done insert to routers table")

    def __insertToRoutersClientTable(self, data):
        connection = sqlite3.connect(self.dbName)
        cursor = connection.cursor()

        for rtr in data.iterkeys():
            for cln in data.get(rtr):
                format_str = """INSERT INTO routers_client (ROUTER, CLIENT)
                                    VALUES ("{router}", "{client}");"""

                sql_command = format_str.format(router=rtr[:17], client=cln)
                cursor.execute(sql_command)

        connection.commit()
        connection.close()

    # ******************
    # ***   Quries   ***
    # ******************

    # run the query at the database and return result
    def __getQuery(self, query):
        connection = sqlite3.connect(self.dbName)
        cursor = connection.cursor()
        cursor.execute(query)
        result = cursor.fetchall()
        connection.close()
        return result

    # return number of users on channel:
    # (channel, connection)
    def getUsersOnChannel(self):
        return self.__getQuery("Select channel, sum(connections) from routers group by channel")

    # return all retransmit by channel
    # (channel, Sent, Retransmit)
    def getPERByChannel(self):
        return self.__getQuery("select channel, sum(packets), sum(retransmit) from session  where channel is not '' and channel > 0 group by channel")

    # return users
    # (MAC)
    def getUsers(self):
        return self.__getQuery("select CLIENT from routers_client")

    # return packets sent in each channel
    # (channel, packets)
    def getPacketsByChannel(self):
        return self.__getQuery("Select channel, sum(packets) from session where channel not like '' and channel not like '0' group by channel")

    # return each user usage
    # (MAC, packets, retransmit packets)
    def getUserUsage(self):
        return self.__getQuery("Select * from usage")

    # return all session
    # (SRC_MAC, DST_MAC, packets, retransmit, channel)
    def getSessions(self):
        return self.__getQuery("select MAC_SRC, MAC_DST, packets, retransmit from session")

    # return all session
    # (ROUTER, CLIENT)
    def getClientsFromRouters(self):
        return self.__getQuery("select * from routers_client")

    # return number of AP
    # (SSID, connection)
    def getRouters(self):
        return self.__getQuery("select SSID, sum(CONNECTIONS) from routers where SSID is not '' group by SSID")

    def getUserSession(self, user):
        query = "select MAC_DST from session where MAC_SRC='" + str(user)[3:-3] + "' and MAC_DST not like 'ff:ff:ff:ff:ff:ff'"
        return self.__getQuery(query)

'''
#DB run example

rtrs = dict()
sses = dict()
usage= dict()

rtrs["FF:FF:FF:FF:FF:FF,4"] = ["toto", 2]
rtrs["TO:ME:RG:AY:GA:DL,11"] = ["toto2", 3]
rtrs["TO:ME:RB:LE:AA:AA,3"] = ["toto3", 11]

sses["FF:FF:FF:FF:FF:FF,TT:TT:TT:TT:TT:TT,1"] = [525,72]
sses["HH:HH:HH:HH:HH:HH,DD:DD:DD:DD:DD:DD,2"] = [285,72]
sses["GG:GG:GG:Gg:GG:GG,YY:YY:YY:YY:YY:YY,3"] = [16,1]

usage["FF:FF:FF:FF:FF:FF"] = [55,7]
usage["HH:HH:HH:HH:HH:HH"] = [25,2]
usage["GG:GG:GG:GG:GG:GG"] = [156,1]

dataTest = DB("test")
dataTest.createDB()

dataTest.insertToTable("routers", rtrs)
dataTest.insertToTable("session", sses)
dataTest.insertToTable("usage", usage)

'''








