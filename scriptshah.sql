USE [master]
GO
/****** Object:  Database [MarinaDynamics365]    Script Date: 30/07/2025 12:27:43 ******/
CREATE DATABASE [MarinaDynamics365]
 CONTAINMENT = NONE
 ON  PRIMARY 
( NAME = N'MarinaDynamics365', FILENAME = N'C:\Program Files\Microsoft SQL Server\MSSQL15.SQLSERVER2019\MSSQL\DATA\MarinaDynamics365.mdf' , SIZE = 13705216KB , MAXSIZE = UNLIMITED, FILEGROWTH = 65536KB )
 LOG ON 
( NAME = N'MarinaDynamics365_log', FILENAME = N'C:\Program Files\Microsoft SQL Server\MSSQL15.SQLSERVER2019\MSSQL\DATA\MarinaDynamics365_log.ldf' , SIZE = 9834432KB , MAXSIZE = 2048GB , FILEGROWTH = 65536KB )
 WITH CATALOG_COLLATION = DATABASE_DEFAULT
GO
ALTER DATABASE [MarinaDynamics365] SET COMPATIBILITY_LEVEL = 150
GO
IF (1 = FULLTEXTSERVICEPROPERTY('IsFullTextInstalled'))
begin
EXEC [MarinaDynamics365].[dbo].[sp_fulltext_database] @action = 'enable'
end
GO
ALTER DATABASE [MarinaDynamics365] SET ANSI_NULL_DEFAULT OFF 
GO
ALTER DATABASE [MarinaDynamics365] SET ANSI_NULLS OFF 
GO
ALTER DATABASE [MarinaDynamics365] SET ANSI_PADDING OFF 
GO
ALTER DATABASE [MarinaDynamics365] SET ANSI_WARNINGS OFF 
GO
ALTER DATABASE [MarinaDynamics365] SET ARITHABORT OFF 
GO
ALTER DATABASE [MarinaDynamics365] SET AUTO_CLOSE OFF 
GO
ALTER DATABASE [MarinaDynamics365] SET AUTO_SHRINK OFF 
GO
ALTER DATABASE [MarinaDynamics365] SET AUTO_UPDATE_STATISTICS ON 
GO
ALTER DATABASE [MarinaDynamics365] SET CURSOR_CLOSE_ON_COMMIT OFF 
GO
ALTER DATABASE [MarinaDynamics365] SET CURSOR_DEFAULT  GLOBAL 
GO
ALTER DATABASE [MarinaDynamics365] SET CONCAT_NULL_YIELDS_NULL OFF 
GO
ALTER DATABASE [MarinaDynamics365] SET NUMERIC_ROUNDABORT OFF 
GO
ALTER DATABASE [MarinaDynamics365] SET QUOTED_IDENTIFIER OFF 
GO
ALTER DATABASE [MarinaDynamics365] SET RECURSIVE_TRIGGERS OFF 
GO
ALTER DATABASE [MarinaDynamics365] SET  DISABLE_BROKER 
GO
ALTER DATABASE [MarinaDynamics365] SET AUTO_UPDATE_STATISTICS_ASYNC OFF 
GO
ALTER DATABASE [MarinaDynamics365] SET DATE_CORRELATION_OPTIMIZATION OFF 
GO
ALTER DATABASE [MarinaDynamics365] SET TRUSTWORTHY OFF 
GO
ALTER DATABASE [MarinaDynamics365] SET ALLOW_SNAPSHOT_ISOLATION OFF 
GO
ALTER DATABASE [MarinaDynamics365] SET PARAMETERIZATION SIMPLE 
GO
ALTER DATABASE [MarinaDynamics365] SET READ_COMMITTED_SNAPSHOT OFF 
GO
ALTER DATABASE [MarinaDynamics365] SET HONOR_BROKER_PRIORITY OFF 
GO
ALTER DATABASE [MarinaDynamics365] SET RECOVERY FULL 
GO
ALTER DATABASE [MarinaDynamics365] SET  MULTI_USER 
GO
ALTER DATABASE [MarinaDynamics365] SET PAGE_VERIFY CHECKSUM  
GO
ALTER DATABASE [MarinaDynamics365] SET DB_CHAINING OFF 
GO
ALTER DATABASE [MarinaDynamics365] SET FILESTREAM( NON_TRANSACTED_ACCESS = OFF ) 
GO
ALTER DATABASE [MarinaDynamics365] SET TARGET_RECOVERY_TIME = 60 SECONDS 
GO
ALTER DATABASE [MarinaDynamics365] SET DELAYED_DURABILITY = DISABLED 
GO
ALTER DATABASE [MarinaDynamics365] SET ACCELERATED_DATABASE_RECOVERY = OFF  
GO
ALTER DATABASE [MarinaDynamics365] SET QUERY_STORE = OFF
GO
USE [MarinaDynamics365]
GO
/****** Object:  User [RemoteUser]    Script Date: 30/07/2025 12:27:43 ******/
CREATE USER [RemoteUser] FOR LOGIN [RemoteUser] WITH DEFAULT_SCHEMA=[dbo]
GO
/****** Object:  UserDefinedFunction [dbo].[AmountToWords]    Script Date: 30/07/2025 12:27:43 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO

CREATE FUNCTION [dbo].[AmountToWords] (@Amount DECIMAL(18, 2))
RETURNS NVARCHAR(200)
AS
BEGIN
    DECLARE @Words NVARCHAR(200)
    DECLARE @Dollars INT
    DECLARE @Cents INT

    SET @Dollars = CAST(FLOOR(@Amount) AS INT)
    SET @Cents = CAST((@Amount - @Dollars) * 100 AS INT)

    SET @Words = dbo.NumberToWords(@Dollars) + ' Dollars'

    IF @Cents > 0
    BEGIN
        SET @Words = @Words + ' and ' + dbo.NumberToWords(@Cents) + ' Cents'
    END

    RETURN @Words
END

GO
/****** Object:  UserDefinedFunction [dbo].[CalCulateOrder]    Script Date: 30/07/2025 12:27:43 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO






CREATE FUNCTION [dbo].[CalCulateOrder](@ItemNumber VARCHAR(50),@locationid VARCHAR(50),@stock float,@min int,@max int) 
RETURNS int 
AS BEGIN
   DECLARE @order int
   
   
 set   @order = case when @stock < @min then @max - @stock else 0 end

   RETURN @order 
END

GO
/****** Object:  UserDefinedFunction [dbo].[CalCulateOrder_by_Max]    Script Date: 30/07/2025 12:27:43 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO








CREATE FUNCTION [dbo].[CalCulateOrder_by_Max](@ItemNumber VARCHAR(50),@locationid VARCHAR(50),@stock float,@max int) 
RETURNS int 
AS BEGIN
   DECLARE @order int
   
   
 set   @order = case when @stock < @max then @max - @stock else 0 end

   RETURN @order 
END

GO
/****** Object:  UserDefinedFunction [dbo].[CalCulateOrder_Max]    Script Date: 30/07/2025 12:27:44 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO







CREATE FUNCTION [dbo].[CalCulateOrder_Max](@ItemNumber VARCHAR(50),@locationid VARCHAR(50),@stock float,@min int,@max int) 
RETURNS int 
AS BEGIN
   DECLARE @order int
   
   
 set   @order = case when @stock < @max then @max - @stock else 0 end

   RETURN @order 
END

GO
/****** Object:  UserDefinedFunction [dbo].[CalCulateOrder_order]    Script Date: 30/07/2025 12:27:44 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO







CREATE FUNCTION [dbo].[CalCulateOrder_order](@stock float,@min int,@max int) 
RETURNS int 
AS BEGIN
   DECLARE @order int
   
   
 set   @order = case when @stock < @min then @max - @stock else 0 end

   RETURN @order 
END

GO
/****** Object:  UserDefinedFunction [dbo].[CalCulateOrder2]    Script Date: 30/07/2025 12:27:44 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO







CREATE FUNCTION [dbo].[CalCulateOrder2](@ItemNumber VARCHAR(50),@locationid VARCHAR(50),@stock float,@min int,@max int) 
RETURNS int 
AS BEGIN
   DECLARE @order int
   
   
 set   @order = case when @stock < @min then @max - @stock else 0 end

   RETURN @order 
END

GO
/****** Object:  UserDefinedFunction [dbo].[ConvertDate2]    Script Date: 30/07/2025 12:27:44 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO

CREATE FUNCTION [dbo].[ConvertDate2]
(
    @inputDate NVARCHAR(4)
)
RETURNS DATE
AS
BEGIN
    DECLARE @month NVARCHAR(2), @day NVARCHAR(2), @year NVARCHAR(4)

    SET @month = LEFT(@inputDate, 2)
    SET @day = RIGHT(@inputDate, 2)
    SET @year = CONVERT(NVARCHAR(4), YEAR(GETDATE())) + RIGHT(@inputDate, 2)

    RETURN CONVERT(DATE, @year + '-' + @month + '-' + @day)
END

GO
/****** Object:  UserDefinedFunction [dbo].[DateConvertShort_Long]    Script Date: 30/07/2025 12:27:44 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO






CREATE FUNCTION [dbo].[DateConvertShort_Long](@inputDate VARCHAR(50)) 
RETURNS datetime 
AS BEGIN
   DECLARE @newdate datetime 
   
   
     select @newdate=CONVERT(datetime, SUBSTRING(@inputDate, 7, 4) + '-' + SUBSTRING(@inputDate, 4, 2) + '-' + SUBSTRING(@inputDate, 1, 2) + ' 00:00:00.000', 120)
	 

   RETURN @newdate 
END

GO
/****** Object:  UserDefinedFunction [dbo].[datediffToWords]    Script Date: 30/07/2025 12:27:44 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO






CREATE FUNCTION [dbo].[datediffToWords] 
( 
    @d1 DATETIME, 
    @d2 DATETIME 
) 
RETURNS VARCHAR(255) 
AS 
BEGIN 
    DECLARE @minutes INT, @word VARCHAR(255) 
    SET @minutes = ABS(DATEDIFF(MINUTE, @d1, @d2)) 
    IF @minutes = 0 
        SET @word = '0 min.' 
    ELSE 
    BEGIN 
        SET @word = '' 
        IF @minutes >= (24*60) 
            SET @word = @word  
            + RTRIM(@minutes/(24*60))+' day, ' 
        SET @minutes = @minutes % (24*60) 
        IF @minutes >= 60 
            SET @word = @word  
            + RTRIM(@minutes/60)+' hrs, ' 
        SET @minutes = @minutes % 60 
        SET @word = @word + RTRIM(@minutes)+' mins' 
    END 
    RETURN @word 
END 


GO
/****** Object:  UserDefinedFunction [dbo].[EST_ACHV_TAR]    Script Date: 30/07/2025 12:27:44 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO








CREATE FUNCTION [dbo].[EST_ACHV_TAR](@sales decimal,@target decimal) 
RETURNS DECIMAL 
AS BEGIN
   DECLARE @Work VARCHAR(250)
   
   --SET @Work = REPLACE(@Work, 'www.', '')
  -- SET @Work = Stuff(@Work,1,4, '')
   --SET @Work = REPLACE(@Work, '.com', '')
   SET @Work = ((((@sales/(right(DATEADD(day, -1, convert(date,GETDATE(),6)),2))) * (DATEDIFF(DAY,GETDATE()-1,DATEADD( MM,DATEDIFF(MM,0,GETDATE())+1,0))-1)) + @sales)/@target)* 100

   RETURN @work 
END






GO
/****** Object:  UserDefinedFunction [dbo].[EST_ACHV_V]    Script Date: 30/07/2025 12:27:44 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO






CREATE FUNCTION [dbo].[EST_ACHV_V](@sales decimal,@target decimal) 
RETURNS DECIMAL 
AS BEGIN
   DECLARE @Work VARCHAR(250)
   
   --SET @Work = REPLACE(@Work, 'www.', '')
  -- SET @Work = Stuff(@Work,1,4, '')
   --SET @Work = REPLACE(@Work, '.com', '')
   SET @Work = (((@sales/right(DATEADD(day, -1, convert(date,GETDATE(),6)),2)) * (DATEDIFF(DAY,GETDATE()-1,DATEADD( MM,DATEDIFF(MM,0,GETDATE())+1,0))-1)) + @sales)

   RETURN @work 
END




GO
/****** Object:  UserDefinedFunction [dbo].[GetAllBranchStock]    Script Date: 30/07/2025 12:27:44 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO











CREATE FUNCTION [dbo].[GetAllBranchStock](@ItemNumber VARCHAR(50)) 
RETURNS DECIMAL 
AS BEGIN
   DECLARE @stock float
   
   SELECT @stock= sum(Stock)
					
	
   FROM [MarinaDynamics365].[dbo].Drug_Batch_Stock_ordered_SUM_PUR
  where [ItemNumber]=@ItemNumber and SiteID not in ('WH0002','WH0001')
  group by [ItemNumber]


   

   RETURN isnull(@stock,0)
END

GO
/****** Object:  UserDefinedFunction [dbo].[GetBonusRefOrder]    Script Date: 30/07/2025 12:27:44 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO







CREATE FUNCTION [dbo].[GetBonusRefOrder](@ItemNumber VARCHAR(50),@Order int) 
RETURNS int 
AS BEGIN
   DECLARE @Bonus int
   
  
    
   SELECT 
     @Bonus= Bonus
     
	
  FROM [MarinaDynamics365].[dbo].[vw_Product_BonusScheme_Details]
  where [ItemNumber]=@ItemNumber and isnull(case when @Order between [FromQty] 
  and [ToQty] then toOrder end,0)<>0

   
   

   RETURN @Bonus 
END

GO
/****** Object:  UserDefinedFunction [dbo].[GetBonusScheme]    Script Date: 30/07/2025 12:27:44 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO








CREATE FUNCTION [dbo].[GetBonusScheme](@ItemNumber VARCHAR(50),@Order int) 
RETURNS varchar(50)
AS BEGIN
   DECLARE @BonusScheme varchar(50)
   
  
    
   SELECT 
     @BonusScheme = BonusScheme 
     
	
  FROM [MarinaDynamics365].[dbo].[vw_Product_BonusScheme_Details]
  where [ItemNumber]=@ItemNumber and isnull(case when @Order between [FromQty] 
  and [ToQty] then toOrder end,0)<>0

   
   

   RETURN @BonusScheme 
END

GO
/****** Object:  UserDefinedFunction [dbo].[GetBranchStock]    Script Date: 30/07/2025 12:27:44 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO










CREATE FUNCTION [dbo].[GetBranchStock](@ItemNumber VARCHAR(50),@locationid VARCHAR(50),@type VARCHAR(50)) 
RETURNS DECIMAL 
AS BEGIN
   DECLARE @stock float
   
   SELECT @stock=  case when @type='Stock' then Stock
						when @type='Transit' then Ordered
						end
							
   
    
     
     
   FROM [MarinaDynamics365].[dbo].Drug_Batch_Stock_ordered_SUM_PUR
  where [ItemNumber]=@ItemNumber and [LocationID]=@locationid


   

   RETURN isnull(@stock,0)
END

GO
/****** Object:  UserDefinedFunction [dbo].[GetCONS]    Script Date: 30/07/2025 12:27:44 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO







CREATE FUNCTION [dbo].[GetCONS](@ItemNumber VARCHAR(50),@locationid VARCHAR(50),@days int) 
RETURNS DECIMAL 
AS BEGIN
   DECLARE @cons int
   
   SELECT @cons= sum([Qty_Sold])
   
    
     
     
  FROM [MarinaDynamics365].[dbo].[SALES_ZERO_STOCK_REF_COMBINED]
  where billdate>=convert(date,getdate()- @days,8) 
  and [ItemNumber]=@ItemNumber and [LocationID]=@locationid
  group by [ItemNumber]
	
		 ,[LocationID]

   
   

   RETURN isnull(@cons,0)
END

GO
/****** Object:  UserDefinedFunction [dbo].[GetCONS_60days]    Script Date: 30/07/2025 12:27:44 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO






CREATE FUNCTION [dbo].[GetCONS_60days](@ItemNumber VARCHAR(50),@locationid VARCHAR(50)) 
RETURNS DECIMAL 
AS BEGIN
   DECLARE @cons int
   
   SELECT @cons= sum([Qty_Sold]) 
   
    
     
     
  FROM [MarinaDynamics365].[dbo].[SALES_ZERO_STOCK_REF_COMBINED_60days]
  where  [ItemNumber]=@ItemNumber and [LocationID]=@locationid

   
   

   RETURN @cons 
END

GO
/****** Object:  UserDefinedFunction [dbo].[GetCONS1]    Script Date: 30/07/2025 12:27:44 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO






CREATE FUNCTION [dbo].[GetCONS1](@ItemNumber VARCHAR(50),@locationid VARCHAR(50),@days int) 
RETURNS DECIMAL 
AS BEGIN
   DECLARE @cons int
   
   
     select @cons=sum(qty_sold) from MarinaDynamics365.dbo.SALES_ZERO_STOCK_REF_COMBINED
	 where Billdate >= convert(date,getdate()- @days,8)  and itemnumber =@ItemNumber and locationid=@locationid

   RETURN @cons 
END

GO
/****** Object:  UserDefinedFunction [dbo].[GetDigitWord]    Script Date: 30/07/2025 12:27:44 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO

CREATE FUNCTION [dbo].[GetDigitWord] (@Digit INT)
RETURNS NVARCHAR(100)
AS
BEGIN
    DECLARE @Word NVARCHAR(100)

    SELECT @Word =
        CASE
            WHEN @Digit >= 100 THEN dbo.GetDigitWord(@Digit / 100) + ' Hundred ' + dbo.GetDigitWord(@Digit % 100)
            WHEN @Digit >= 90 THEN 'Ninety ' + dbo.GetDigitWord(@Digit % 90)
            WHEN @Digit >= 80 THEN 'Eighty ' + dbo.GetDigitWord(@Digit % 80)
            WHEN @Digit >= 70 THEN 'Seventy ' + dbo.GetDigitWord(@Digit % 70)
            WHEN @Digit >= 60 THEN 'Sixty ' + dbo.GetDigitWord(@Digit % 60)
            WHEN @Digit >= 50 THEN 'Fifty ' + dbo.GetDigitWord(@Digit % 50)
            WHEN @Digit >= 40 THEN 'Forty ' + dbo.GetDigitWord(@Digit % 40)
            WHEN @Digit >= 30 THEN 'Thirty ' + dbo.GetDigitWord(@Digit % 30)
            WHEN @Digit >= 20 THEN 'Twenty ' + dbo.GetDigitWord(@Digit % 20)
            WHEN @Digit = 19 THEN 'Nineteen'
            WHEN @Digit = 18 THEN 'Eighteen'
            WHEN @Digit = 17 THEN 'Seventeen'
            WHEN @Digit = 16 THEN 'Sixteen'
            WHEN @Digit = 15 THEN 'Fifteen'
            WHEN @Digit = 14 THEN 'Fourteen'
            WHEN @Digit = 13 THEN 'Thirteen'
            WHEN @Digit = 12 THEN 'Twelve'
            WHEN @Digit = 11 THEN 'Eleven'
            WHEN @Digit = 10 THEN 'Ten'
            WHEN @Digit = 9 THEN 'Nine'
            WHEN @Digit = 8 THEN 'Eight'
            WHEN @Digit = 7 THEN 'Seven'
            WHEN @Digit = 6 THEN 'Six'
            WHEN @Digit = 5 THEN 'Five'
            WHEN @Digit = 4 THEN 'Four'
            WHEN @Digit = 3 THEN 'Three'
            WHEN @Digit = 2 THEN 'Two'
            WHEN @Digit = 1 THEN 'One'
            ELSE ''
        END

    RETURN @Word
END

GO
/****** Object:  UserDefinedFunction [dbo].[GetLatestReceive_date]    Script Date: 30/07/2025 12:27:44 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO










CREATE FUNCTION [dbo].[GetLatestReceive_date](
    @ItemNumber VARCHAR(50),
    @StoreCode VARCHAR(50)
) 
RETURNS DATETIME
AS 
BEGIN
    DECLARE @date DATETIME;
   
    SELECT @date = MAX([RequestedReceiptDate])
    FROM [MarinaDynamics365].[dbo].[TransferOrders_Latest_Received]
    WHERE [ItemNumber] = @ItemNumber 
      AND [ReceivingWarehouseId] = @StoreCode;

    RETURN @date;
END;

GO
/****** Object:  UserDefinedFunction [dbo].[GetLatestReceive_Qty]    Script Date: 30/07/2025 12:27:44 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO





CREATE FUNCTION [dbo].[GetLatestReceive_Qty](
    @ItemNumber VARCHAR(50),
    @StoreCode VARCHAR(50)
) 
RETURNS int
AS 
BEGIN
    DECLARE @qty int
   
    SELECT @qty = [ReceivedQuantity]
    FROM [MarinaDynamics365].[dbo].[TransferOrders_Latest_Received]
    WHERE [ItemNumber] = @ItemNumber 
      AND [ReceivingWarehouseId] = @StoreCode;

    RETURN @qty;
END;

GO
/****** Object:  UserDefinedFunction [dbo].[GetMaxQtySold]    Script Date: 30/07/2025 12:27:44 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO








CREATE FUNCTION [dbo].[GetMaxQtySold](@ItemNumber VARCHAR(50),@locationid VARCHAR(50),@days int) 
RETURNS DECIMAL 
AS BEGIN
   DECLARE @max_qty decimal(8,2)
   
   SELECT @max_qty= max([Qty_Sold])
   
    
     
     
  FROM [MarinaDynamics365].[dbo].[SALES_ZERO_STOCK_REF_COMBINED]
  where billdate>=convert(date,getdate()- @days,8) 
  and [ItemNumber]=@ItemNumber and [LocationID]=@locationid
  
   
   

   RETURN isnull(@max_qty,0)
END

GO
/****** Object:  UserDefinedFunction [dbo].[GetOrderRefBonus]    Script Date: 30/07/2025 12:27:44 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO









CREATE FUNCTION [dbo].[GetOrderRefBonus](@ItemNumber VARCHAR(50),@Order int) 
RETURNS int 
AS BEGIN
   DECLARE @Order_Final int
   
   
    
   SELECT 
     @Order_Final= [ToOrder]
     
	
  FROM [MarinaDynamics365].[dbo].[vw_Product_BonusScheme_Details]
  where [ItemNumber]=@ItemNumber and isnull(case when @Order between [FromQty] 
  and [ToQty] then toOrder end,0)<>0

   
   

   RETURN @Order_Final
END

GO
/****** Object:  UserDefinedFunction [dbo].[GetPrice]    Script Date: 30/07/2025 12:27:44 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO











CREATE FUNCTION [dbo].[GetPrice](@ItemNumber VARCHAR(50), @type VARCHAR(50)) 
RETURNS DECIMAL(10,2) -- Specify precision and scale here
AS 
BEGIN
   DECLARE @price DECIMAL(10,2) -- Ensure this also matches the return type
   
   SELECT @price = case when @type='Retail' then Selling_Price
					when @type='Cost' then  cost end

   FROM [MarinaDynamics365].[dbo].[Mx_Product_w_Price_Tax]
   WHERE [ItemNumber] = @ItemNumber

   RETURN @price
END
GO
/****** Object:  UserDefinedFunction [dbo].[GetWHStock]    Script Date: 30/07/2025 12:27:44 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO










CREATE FUNCTION [dbo].[GetWHStock](@ItemNumber VARCHAR(50),@type VARCHAR(50)) 
RETURNS DECIMAL 
AS BEGIN
   DECLARE @stock float
   
   SELECT @stock=  sum(case when @type='Stock' then Stock
						when @type='Transit' then Ordered
						end)
							
   
    
     
     
   FROM [MarinaDynamics365].[dbo].[Drug_Batch_Stock_ordered_SUM]
  where [ItemNumber]=@ItemNumber and [LocationID] in (35,51)
  group by ItemNumber,LocationID

   

   RETURN isnull(@stock,0)
END

GO
/****** Object:  UserDefinedFunction [dbo].[NumberToWords]    Script Date: 30/07/2025 12:27:44 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO

CREATE FUNCTION [dbo].[NumberToWords] (@Number INT)
RETURNS NVARCHAR(100)
AS
BEGIN
    DECLARE @Words NVARCHAR(100)

    IF @Number = 0
        SET @Words = 'Zero'
    ELSE
        SELECT @Words = 
            CASE
                WHEN @Number >= 1000 THEN dbo.GetDigitWord(@Number / 1000) + ' Thousand ' + dbo.GetDigitWord(@Number % 1000)
                WHEN @Number >= 100  THEN dbo.GetDigitWord(@Number / 100) + ' Hundred ' + dbo.GetDigitWord(@Number % 100)
                ELSE dbo.GetDigitWord(@Number)
            END

    RETURN @Words
END

GO
/****** Object:  UserDefinedFunction [dbo].[RemoveCharSpecialSymbolValue]    Script Date: 30/07/2025 12:27:44 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO




Create function [dbo].[RemoveCharSpecialSymbolValue](@str varchar(500))  
returns varchar(500)  
begin  
declare @startingIndex int  
set @startingIndex=0  
while 1=1  
begin  
set @startingIndex= patindex('%[^0-9.]%',@str)  
if @startingIndex <> 0  
begin  
set @str = replace(@str,substring(@str,@startingIndex,1),'x')  
end  
else break;  
end  
return @str  
end 
GO
/****** Object:  UserDefinedFunction [dbo].[SecTimeDay]    Script Date: 30/07/2025 12:27:44 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO



CREATE function [dbo].[SecTimeDay] (@sec integer)
returns varchar(19)
as
begin

declare @DayTime varchar(19)

/* Calculate # of days and display if necessary */
Select @DayTime = Case When @Sec >= 86400
                Then Convert(VarChar(5), @Sec/86400)
                + ' days '
                Else ''
                End
/* Add HH:MM:SS to number of days (or ') for output */
       + Convert(VarChar(8), DateAdd(Second, @Sec, 0), 108)

return @DayTime

end
GO
/****** Object:  UserDefinedFunction [dbo].[SplitStringByDash]    Script Date: 30/07/2025 12:27:44 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE FUNCTION [dbo].[SplitStringByDash]
(
    @InputString NVARCHAR(MAX)
)
RETURNS @ResultTable TABLE
(
    PartNumber INT,
    Part NVARCHAR(MAX)
)
AS
BEGIN
    DECLARE @Pos INT, @Part NVARCHAR(MAX), @PartIndex INT = 1;

    -- Ensure the string ends with a delimiter to capture the last part
    SET @InputString = @InputString + '-'

    WHILE CHARINDEX('-', @InputString) > 0
    BEGIN
        -- Find the position of the first dash
        SET @Pos = CHARINDEX('-', @InputString);

        -- Extract the part before the dash
        SET @Part = LEFT(@InputString, @Pos - 1);

        -- Insert the part into the result table
        INSERT INTO @ResultTable (PartNumber, Part)
        VALUES (@PartIndex, @Part);

        -- Remove the processed part from the input string
        SET @InputString = SUBSTRING(@InputString, @Pos + 1, LEN(@InputString));

        -- Increment the part index
        SET @PartIndex = @PartIndex + 1;
    END;

    RETURN;
END;

GO
/****** Object:  UserDefinedFunction [dbo].[udfTrim]    Script Date: 30/07/2025 12:27:44 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO

CREATE FUNCTION [dbo].[udfTrim] 
(
	@StringToClean as varchar(8000)
)
RETURNS varchar(8000)
AS
BEGIN	
	--Replace all non printing whitespace characers with Characer 32 whitespace
	--NULL
	Set @StringToClean = Replace(@StringToClean,CHAR(0),CHAR(32));
	--Horizontal Tab
	Set @StringToClean = Replace(@StringToClean,CHAR(9),CHAR(32));
	--Line Feed
	Set @StringToClean = Replace(@StringToClean,CHAR(10),CHAR(32));
	--Vertical Tab
	Set @StringToClean = Replace(@StringToClean,CHAR(11),CHAR(32));
	--Form Feed
	Set @StringToClean = Replace(@StringToClean,CHAR(12),CHAR(32));
	--Carriage Return
	Set @StringToClean = Replace(@StringToClean,CHAR(13),CHAR(32));
	--Column Break
	Set @StringToClean = Replace(@StringToClean,CHAR(14),CHAR(32));
	--Non-breaking space
	Set @StringToClean = Replace(@StringToClean,CHAR(160),CHAR(32));

	Set @StringToClean = LTRIM(RTRIM(@StringToClean));
	Return @StringToClean
END
GO
/****** Object:  Table [dbo].[SALES_ZERO_STOCK_REF_COMBINED]    Script Date: 30/07/2025 12:27:44 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[SALES_ZERO_STOCK_REF_COMBINED](
	[Bill_No] [nvarchar](12) NOT NULL,
	[Drug_id] [nvarchar](25) NOT NULL,
	[Qty_Sold] [money] NULL,
	[total_value] [money] NULL,
	[Category] [nvarchar](50) NULL,
	[LocationID] [int] NOT NULL,
	[Billdate] [datetime] NULL,
	[DrugName] [nvarchar](100) NOT NULL,
	[Brand_Name] [nvarchar](50) NULL,
	[ManfName] [nvarchar](100) NULL,
	[Cust_Name] [nvarchar](50) NULL,
	[batchid] [int] NOT NULL,
	[salesmanname] [nvarchar](50) NULL,
	[cost] [money] NULL,
	[PromoItem] [money] NULL,
	[QTYActual] [money] NULL,
	[FromGroup] [nvarchar](50) NULL,
	[ItemNumber] [nchar](10) NULL
) ON [PRIMARY]
GO
/****** Object:  View [dbo].[vw_SALES_ZERO_STOCK_REF_COMBINED_60days]    Script Date: 30/07/2025 12:27:44 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO


create view [dbo].[vw_SALES_ZERO_STOCK_REF_COMBINED_60days]
as
SELECT  [ItemNumber]
		
		 ,[LocationID]
      ,sum([Qty_Sold]) [Qty_Sold]
   
    
     
     
  FROM [MarinaDynamics365].[dbo].[SALES_ZERO_STOCK_REF_COMBINED]
  where billdate>=convert(date,getdate()- 61,8) 
  group by [ItemNumber]
	
		 ,[LocationID]
GO
/****** Object:  Table [dbo].[REORDER_Branch_hierarchy]    Script Date: 30/07/2025 12:27:44 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[REORDER_Branch_hierarchy](
	[SNo] [varchar](50) NULL,
	[STORECODE] [varchar](50) NULL,
	[ShortName] [varchar](50) NULL,
	[LocationName] [varchar](150) NULL
) ON [PRIMARY]
GO
/****** Object:  Table [dbo].[Drug_Batch_Stock_ordered_SUM_STORE]    Script Date: 30/07/2025 12:27:44 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[Drug_Batch_Stock_ordered_SUM_STORE](
	[ItemNumber] [nvarchar](max) NULL,
	[Drug_id] [varchar](50) NULL,
	[Stock] [float] NULL,
	[Ordered] [float] NULL,
	[SiteID] [nvarchar](max) NULL,
	[Locationid] [varchar](50) NULL
) ON [PRIMARY] TEXTIMAGE_ON [PRIMARY]
GO
/****** Object:  Table [dbo].[MX_Product_MinMax_Price_Vendor_Stock_re_order]    Script Date: 30/07/2025 12:27:44 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[MX_Product_MinMax_Price_Vendor_Stock_re_order](
	[ItemNumber] [nvarchar](max) NULL,
	[ProductName] [nvarchar](max) NULL,
	[ProductGroupId] [nvarchar](max) NULL,
	[RetailProductCategoryname] [nvarchar](max) NULL,
	[SalesSalesTaxItemGroupCode] [nvarchar](max) NULL,
	[Drug_id] [varchar](50) NULL,
	[STORECODE] [varchar](50) NULL,
	[LocationID] [varchar](50) NULL,
	[ShortName] [varchar](50) NULL,
	[Min] [varchar](50) NOT NULL,
	[Max] [varchar](50) NOT NULL,
	[Cost] [varchar](50) NULL,
	[Price] [varchar](50) NULL,
	[Vendor] [varchar](50) NULL,
	[Stock] [float] NOT NULL,
	[CONS] [money] NOT NULL,
	[Pending_Stock] [float] NOT NULL,
	[Ordered] [float] NOT NULL,
	[Unposted_Qty] [numeric](38, 2) NULL,
	[Warehouse] [varchar](50) NOT NULL,
	[Stock_after_Unposted] [float] NOT NULL,
	[Qty_Unposted] [decimal](38, 2) NOT NULL,
	[Pending_Qty_TO_Created] [float] NOT NULL
) ON [PRIMARY] TEXTIMAGE_ON [PRIMARY]
GO
/****** Object:  Table [dbo].[Mx_Product_Category_v2]    Script Date: 30/07/2025 12:27:44 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[Mx_Product_Category_v2](
	[Item number] [varchar](50) NULL,
	[Product name] [varchar](254) NULL,
	[Old Category] [varchar](50) NULL,
	[Agent Name] [varchar](254) NULL
) ON [PRIMARY]
GO
/****** Object:  View [dbo].[vw_FEB2024_MinMax_RE_Order_Branch_Final]    Script Date: 30/07/2025 12:27:44 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO




















create view [dbo].[vw_FEB2024_MinMax_RE_Order_Branch_Final]
as

SELECT [ItemNumber]
      ,[ProductName]
      ,[ProductGroupId]
      ,[RetailProductCategoryname]
      ,[SalesSalesTaxItemGroupCode]
      ,[Drug_id]
      ,[STORECODE]
      ,[LocationID]
      ,[ShortName]
      ,cast([Min] as int) [Min]
      ,cast([Max] as int) [Max]
      ,[Cost]
      ,[Price]
      ,[Vendor]
      ,floor([Stock]) [Stock]
      ,[Pending_Stock]
	-- , [dbo].[CalCulateOrder]([ItemNumber],[LocationID],(floor([Stock])-floor(Unposted_Qty)) +Ordered+[Pending_Stock],[Min],[Max]) [Order]
	  , [dbo].[CalCulateOrder]([ItemNumber],[LocationID],floor([Stock_after_Unposted]) +Ordered,[Min],[Max]) [Order]
 --, [dbo].[CalCulateOrder]([ItemNumber],[LocationID],floor([Stock]) +Ordered+[Pending_Stock],[Min],[Max]) [Order]
	  ,floor(CONS) CONS
	   ,(Select Sno from REORDER_Branch_hierarchy h
	  where h.[STORECODE]=f.[STORECODE]  ) turn
	 ,isnull((SELECT 
								    [Stock]
									FROM [MarinaDynamics365].[dbo].Drug_Batch_Stock_ordered_SUM_STORE s
									where s.[ItemNumber]=f.[ItemNumber] ),0) Store_Stock

	  ,(SELECT [Old Category]
     
  FROM [MarinaDynamics365].[dbo].[Mx_Product_Category_v2] m
  where m.[Item number]=f.ItemNumber) Category
	  ,Ordered
	  ,Unposted_Qty
	,  Qty_Unposted
	  ,floor(Stock_after_Unposted) Stock_after_Unposted
  FROM [MarinaDynamics365].[dbo].MX_Product_MinMax_Price_Vendor_Stock_re_order f
  where  CONS+[Min]+[Max]+[Stock]<>0
  and [STORECODE] not in ('WH0001','WH0002')
  and [STORECODE] in (Select [STORECODE]  FROM [MarinaDynamics365].[dbo].[REORDER_Branch_hierarchy])
  and WAREHOUSE='MARINA'
GO
/****** Object:  Table [dbo].[ProductSpecificUnitOfMeasureConversions]    Script Date: 30/07/2025 12:27:44 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[ProductSpecificUnitOfMeasureConversions](
	[ProductNumber] [int] NULL,
	[FromUnitSymbol] [varchar](255) NULL,
	[ToUnitSymbol] [varchar](255) NULL,
	[Factor] [int] NULL,
	[InnerOffset] [int] NULL,
	[OuterOffset] [int] NULL,
	[Rounding] [varchar](255) NULL,
	[Denominator] [int] NULL,
	[Numerator] [int] NULL
) ON [PRIMARY]
GO
/****** Object:  View [dbo].[vw_ProductSpecificUnitOfMeasureConversions_pcs]    Script Date: 30/07/2025 12:27:44 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE VIEW [dbo].[vw_ProductSpecificUnitOfMeasureConversions_pcs]
AS
SELECT        ProductNumber, Factor
FROM            dbo.ProductSpecificUnitOfMeasureConversions
WHERE        (ToUnitSymbol = 'Pcs') AND (FromUnitSymbol = 'Pack') AND (Factor <> 1) OR
                         (ToUnitSymbol = 'Pcs') AND (FromUnitSymbol = 'bottle') AND (Factor <> 1)
GROUP BY ProductNumber, Factor
GO
/****** Object:  Table [dbo].[Drug_Batch_Stock_ordered_SUM_800STORE]    Script Date: 30/07/2025 12:27:44 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[Drug_Batch_Stock_ordered_SUM_800STORE](
	[ItemNumber] [nvarchar](max) NULL,
	[Drug_id] [varchar](50) NULL,
	[Stock] [float] NULL,
	[Ordered] [float] NULL,
	[SiteID] [nvarchar](max) NULL,
	[Locationid] [varchar](50) NULL
) ON [PRIMARY] TEXTIMAGE_ON [PRIMARY]
GO
/****** Object:  View [dbo].[vw_FEB2024_MinMax_RE_Order_Branch_Final_800]    Script Date: 30/07/2025 12:27:44 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO



















create view [dbo].[vw_FEB2024_MinMax_RE_Order_Branch_Final_800]
as

SELECT [ItemNumber]
      ,[ProductName]
      ,[ProductGroupId]
      ,[RetailProductCategoryname]
      ,[SalesSalesTaxItemGroupCode]
      ,[Drug_id]
      ,[STORECODE]
      ,[LocationID]
      ,[ShortName]
      ,cast([Min] as int) [Min]
      ,cast([Max] as int) [Max]
      ,[Cost]
      ,[Price]
      ,[Vendor]
      ,floor([Stock]) [Stock]
      ,[Pending_Stock]
	-- , [dbo].[CalCulateOrder]([ItemNumber],[LocationID],(floor([Stock])-floor(Unposted_Qty))+Ordered+[Pending_Stock],[Min],[Max]) [Order]
	  , [dbo].[CalCulateOrder]([ItemNumber],[LocationID],floor(Stock_after_Unposted)+Ordered,[Min],[Max]) [Order]
	  ,floor(CONS) CONS
	   ,(Select Sno from REORDER_Branch_hierarchy h
	  where h.[STORECODE]=f.[STORECODE]  ) turn
	 ,isnull((SELECT 
								    [Stock]
									FROM [MarinaDynamics365].[dbo].Drug_Batch_Stock_ordered_SUM_800STORE s
									where s.[ItemNumber]=f.[ItemNumber] ),0) Store_Stock
  ,(SELECT [Old Category]
     
  FROM [MarinaDynamics365].[dbo].[Mx_Product_Category_v2] m
  where m.[Item number]=f.ItemNumber) Category
	  ,Ordered
	  ,Unposted_Qty
	  	,  Qty_Unposted
	  ,floor(Stock_after_Unposted) Stock_after_Unposted
  FROM [MarinaDynamics365].[dbo].MX_Product_MinMax_Price_Vendor_Stock_re_order f
  where  CONS+[Min]+[Max]+[Stock]<>0
  and [STORECODE] not in ('WH0001','WH0002')
  and [STORECODE] in (Select [STORECODE]  FROM [MarinaDynamics365].[dbo].[REORDER_Branch_hierarchy])
  and WAREHOUSE='800'
GO
/****** Object:  Table [dbo].[Drug_Master_800Store]    Script Date: 30/07/2025 12:27:44 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[Drug_Master_800Store](
	[Drug_id] [varchar](50) NULL,
	[DrugName] [varchar](254) NULL
) ON [PRIMARY]
GO
/****** Object:  Table [dbo].[Mx_Product_Master]    Script Date: 30/07/2025 12:27:44 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[Mx_Product_Master](
	[Item number] [varchar](50) NULL,
	[Product name] [varchar](254) NULL,
	[Old_Drug_ID_Prefix] [varchar](50) NULL,
	[DrugName] [varchar](254) NULL,
	[Drug_ID] [varchar](50) NULL,
	[ITEMGROUP] [varchar](50) NULL,
	[RECID] [varchar](50) NULL,
	[PRODUCT] [varchar](50) NULL,
	[PRODUCTNAME] [varchar](254) NULL,
	[Brand_name] [varchar](254) NULL,
	[Sub_Category] [varchar](254) NULL,
	[Comments] [varchar](max) NULL
) ON [PRIMARY] TEXTIMAGE_ON [PRIMARY]
GO
/****** Object:  Table [dbo].[Mx_StoreCode]    Script Date: 30/07/2025 12:27:44 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[Mx_StoreCode](
	[STORECODE] [varchar](50) NULL,
	[STORENAME] [varchar](50) NULL,
	[REGION] [varchar](50) NULL,
	[DIVISION] [varchar](50) NULL,
	[LocationID] [varchar](50) NULL,
	[ShortName] [varchar](50) NULL,
	[LocationName] [varchar](150) NULL
) ON [PRIMARY]
GO
/****** Object:  Table [dbo].[Purchase_ReOrderUpload_RAW]    Script Date: 30/07/2025 12:27:44 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[Purchase_ReOrderUpload_RAW](
	[Item number] [varchar](50) NULL,
	[Product name] [varchar](254) NULL,
	[Requirement quantity] [varchar](50) NULL,
	[Warehouse2] [varchar](50) NULL
) ON [PRIMARY]
GO
/****** Object:  Table [dbo].[Drug_Master]    Script Date: 30/07/2025 12:27:44 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[Drug_Master](
	[Drug_id] [nvarchar](25) NOT NULL,
	[DrugName] [nvarchar](100) NOT NULL,
	[Meas_Qty] [nvarchar](50) NULL,
	[Meas_type] [nvarchar](50) NULL,
	[DrugType] [nvarchar](50) NULL,
	[Qty_Unit] [int] NULL,
	[Manf_id] [nvarchar](6) NULL,
	[Comments] [nvarchar](100) NULL,
	[Activate] [smallint] NOT NULL,
	[DrugSelection] [nvarchar](50) NULL,
	[Category] [nvarchar](50) NULL,
	[GenericName] [nvarchar](50) NULL,
	[Control] [nvarchar](50) NULL,
	[Bin_Number] [nvarchar](50) NULL,
	[ItemCode] [nvarchar](50) NULL,
	[GName] [nvarchar](50) NULL,
	[Brand_Name] [nvarchar](50) NULL,
	[MaxiMumDiscount] [int] NULL,
	[Expiry] [nvarchar](50) NULL,
	[LineID] [int] NULL,
	[DateCreated] [datetime] NULL,
	[User] [nvarchar](50) NULL,
	[DateUpdated] [datetime] NULL,
	[SP1] [money] NULL,
	[SP2] [money] NULL,
	[SP3] [money] NULL,
	[UnitCost] [money] NULL,
	[LPOForSupplier] [nvarchar](50) NULL,
	[SupplierCode] [nvarchar](50) NULL,
	[BulkItemForLPO] [nvarchar](50) NULL,
	[GroupName1] [nvarchar](50) NULL,
	[GroupName2] [nvarchar](50) NULL,
	[GroupName3] [nvarchar](50) NULL,
	[TaxPercent] [money] NULL,
	[ArabicName] [nvarchar](255) NULL,
	[Comments2] [varchar](256) NULL
) ON [PRIMARY]
GO
/****** Object:  View [dbo].[vw_Purchase_ReOrder]    Script Date: 30/07/2025 12:27:44 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO



create view [dbo].[vw_Purchase_ReOrder]
as
SELECT [Item number]
      ,[Product name]
      ,cast(ceiling([Requirement quantity]) as int) [ReOrder]
      ,[Warehouse2]
	  ,(Select Shortname from dbo.Mx_StoreCode loc
	  where loc.STORECODE=REPLACE(
            REPLACE(
                REPLACE(r.[Warehouse2]  , CHAR(13) + CHAR(10), ''), -- Removes newline characters
            CHAR(13), ''), -- Removes line feed characters
        ',', '')
	  
	  
	  
	  
	  ) Shortname

	  ,(Select dm.Category from Mx_Product_Master g,
	  [MarinaDynamics365].[dbo].Drug_MASter dm
	  where g.[Item number]=r.[Item number] and g.Drug_ID=dm.drug_id) Category
	  ,(Select dm.Brand_Name from Mx_Product_Master g,
	  [MarinaDynamics365].[dbo].Drug_MASter dm
	  where g.[Item number]=r.[Item number] and g.Drug_ID=dm.drug_id) Brand_Name

	   ,(Select dm.GEnericName from Mx_Product_Master g,
	  [MarinaDynamics365].[dbo].Drug_MASter dm
	  where g.[Item number]=r.[Item number] and g.Drug_ID=dm.drug_id) Sub_Category


	  ,isnull(((Select dm.drug_id from Mx_Product_Master g,
	  [MarinaDynamics365].[dbo].Drug_Master_800Store dm
	  where g.[Item number]=r.[Item number] and g.Drug_ID=dm.drug_id)),1) Store

  FROM [MarinaDynamics365].[dbo].[Purchase_ReOrderUpload_RAW] r
GO
/****** Object:  Table [dbo].[Drug_Manufacturer_Consignment_Policy]    Script Date: 30/07/2025 12:27:44 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[Drug_Manufacturer_Consignment_Policy](
	[Manf_id] [varchar](50) NULL,
	[ManfName] [varchar](254) NULL,
	[Brand Name] [varchar](50) NULL,
	[Policy] [varchar](254) NULL,
	[Return_Trigger_Days] [varchar](50) NULL
) ON [PRIMARY]
GO
/****** Object:  Table [dbo].[ProductMaster_Upload]    Script Date: 30/07/2025 12:27:44 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[ProductMaster_Upload](
	[Product Id] [varchar](50) NULL,
	[Product Name] [varchar](254) NULL,
	[Unit] [varchar](50) NULL,
	[Brand] [varchar](50) NULL,
	[Main Category] [varchar](50) NULL,
	[Category] [varchar](50) NULL,
	[Sub Category 1] [varchar](50) NULL,
	[Is Marina] [varchar](50) NULL,
	[Supplier Id] [varchar](50) NULL,
	[Supplier] [varchar](254) NULL,
	[unit cost] [varchar](50) NULL,
	[Sales Price] [varchar](50) NULL,
	[Aggrement_Cost] [varchar](50) NULL,
	[Retail Price] [varchar](50) NULL,
	[Hotel Price] [varchar](50) NULL,
	[Sales Tax] [varchar](50) NULL,
	[Purch Tax] [varchar](50) NULL,
	[Is Active] [varchar](50) NULL
) ON [PRIMARY]
GO
/****** Object:  Table [dbo].[Expiry_items_Upload]    Script Date: 30/07/2025 12:27:44 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[Expiry_items_Upload](
	[Item number] [varchar](50) NULL,
	[Product name] [varchar](254) NULL,
	[Consignment item] [varchar](50) NULL,
	[Bonus Item] [varchar](50) NULL,
	[Warehouse] [varchar](50) NULL,
	[Batch number] [varchar](50) NULL,
	[Location] [varchar](50) NULL,
	[Warehouse Name] [varchar](50) NULL,
	[Primary Vendor] [varchar](50) NULL,
	[Vendor Name] [varchar](254) NULL,
	[Batch disposition code] [varchar](150) NULL,
	[Batch disposition status] [varchar](150) NULL,
	[Manufacturing date] [varchar](50) NULL,
	[Shelf life period in days] [varchar](50) NULL,
	[Expiration date] [varchar](50) NULL,
	[Physical inventory] [varchar](50) NULL,
	[Physical reserved] [varchar](50) NULL,
	[Available physical] [varchar](50) NULL,
	[Ordered] [varchar](50) NULL,
	[Ordered reserved] [varchar](50) NULL,
	[Total available] [varchar](50) NULL
) ON [PRIMARY]
GO
/****** Object:  View [dbo].[vw_RETURN_Policy_data]    Script Date: 30/07/2025 12:27:44 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO


create view [dbo].[vw_RETURN_Policy_data]
as
SELECT  [Item number] [Drug_id]
      ,[Product name] [DrugName]
      ,'' [SubCategory]
      ,[Primary Vendor] [Manf_id]
	  ,(select [Brand] FROM [MarinaDynamics365].[dbo].[ProductMaster_Upload] b
	  where b.[Product Id]=s.[Item number]) Brand_Name
	  	  ,(select [unit cost] FROM [MarinaDynamics365].[dbo].[ProductMaster_Upload] b
	  where b.[Product Id]=s.[Item number]) [Cost]
	 , [Vendor Name] [Agent_Name]
	 		,(Select [Policy] from Drug_Manufacturer_Consignment_Policy p 
	  where p.[Manf_id]=s.[Primary Vendor]) [Return_Type]
	, REPLACE(RIGHT(CONVERT(varchar, CONVERT(date, dbo.DateConvertShort_Long([Expiration date])), 5), 5), '-', '') AS BatchNo_New
      ,[Batch number] [Batch_No]
      ,dbo.DateConvertShort_Long([Expiration date]) [ExpDate]
      ,CASE WHEN warehouse LIKE '%TW' THEN CAST([Physical inventory] AS FLOAT) ELSE CAST([Total available] AS FLOAT) 
                         END  Stock 
						  
     ,[Warehouse]
    , (select locationid from MarinaDynamics365.dbo.Mx_StoreCode l
	where l.STORECODE=replace(s.Warehouse,'-TW',''))[LocationID]
	  , 		(Select [Policy] from [MarinaDynamics365].dbo.Drug_Manufacturer_Consignment_Policy p 
	  where p.[Manf_id]=s.[Primary Vendor])   [Return_Policy]
			
				  , isnull(
		
		(Select [Return_Trigger_days] from Drug_Manufacturer_Consignment_Policy p 
	  where p.[Manf_id]=s.[Primary Vendor]),0)
			
		 [Return_Trigger_days]
		


		,	
				case when datediff(DAY,DATEADD(month, DATEDIFF(month, 0, GETDATE()), 0) , DATEADD(DAY, 1 - DATEPART(DAY, dbo.DateConvertShort_Long([Expiration date])), dbo.DateConvertShort_Long([Expiration date])) ) <= 
		 
	
		
		(Select [Return_Trigger_days] from Drug_Manufacturer_Consignment_Policy p 
	  where p.[Manf_id]=s.[Primary Vendor])
			

			 then 'Return: ' + Convert(varchar,datediff(DAY,DATEADD(month, DATEDIFF(month, 0, GETDATE()), 0) ,DATEADD(DAY, 1 - DATEPART(DAY,dbo.DateConvertShort_Long([Expiration date])), dbo.DateConvertShort_Long([Expiration date])))) +
			' days Before Expry' else ''  end
		
	
		
		Remarks
		, CASE WHEN (select locationid from MarinaDynamics365.dbo.Mx_StoreCode l
	where l.STORECODE=replace(s.Warehouse,'-TW','')) = 99 THEN 'Expiry' ELSE 'Branch' END AS Loc_Grp



		FROM [MarinaDynamics365].[dbo].[Expiry_items_Upload] s
		where CASE WHEN warehouse LIKE '%TW' THEN CAST([Physical inventory] AS FLOAT) ELSE CAST([Total available] AS FLOAT) 
                         END  >0


		and dbo.DateConvertShort_Long([Expiration date])>'2024-11-01'
	
	

  
GO
/****** Object:  Table [dbo].[ReleasedProductCreationsV2]    Script Date: 30/07/2025 12:27:44 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[ReleasedProductCreationsV2](
	[dataAreaId] [nvarchar](max) NULL,
	[ItemNumber] [nvarchar](max) NULL,
	[PurchaseUnitSymbol] [nvarchar](max) NULL,
	[ProductGroupId] [nvarchar](max) NULL,
	[ProductType] [nvarchar](max) NULL,
	[WarrantyDurationTime] [bigint] NULL,
	[InventoryUnitSymbol] [nvarchar](max) NULL,
	[WarrantablePriceRangeBaseType] [nvarchar](max) NULL,
	[UpperWarrantablePriceRangeLimit] [float] NULL,
	[RetailProductCategoryname] [nvarchar](max) NULL,
	[InventoryReservationHierarchyName] [nvarchar](max) NULL,
	[StorageDimensionGroupName] [nvarchar](max) NULL,
	[ProductNumber] [nvarchar](max) NULL,
	[ProductSubType] [nvarchar](max) NULL,
	[BOMUnitSymbol] [nvarchar](max) NULL,
	[SearchName] [nvarchar](max) NULL,
	[ServiceType] [nvarchar](max) NULL,
	[WarrantyDurationTimeUnit] [nvarchar](max) NULL,
	[VariantConfigurationTechnology] [nvarchar](max) NULL,
	[ProductDimensionGroupName] [nvarchar](max) NULL,
	[IsProductKit] [nvarchar](max) NULL,
	[SalesSalesTaxItemGroupCode] [nvarchar](max) NULL,
	[SalesUnitSymbol] [nvarchar](max) NULL,
	[IsCatchWeightProduct] [nvarchar](max) NULL,
	[ProductDescription] [nvarchar](max) NULL,
	[LowerWarrantablePriceRangeLimit] [float] NULL,
	[TrackingDimensionGroupName] [nvarchar](max) NULL,
	[ProductSearchName] [nvarchar](max) NULL,
	[PurchaseSalesTaxItemGroupCode] [nvarchar](max) NULL,
	[ProductName] [nvarchar](max) NULL,
	[ItemModelGroupId] [nvarchar](max) NULL
) ON [PRIMARY] TEXTIMAGE_ON [PRIMARY]
GO
/****** Object:  Table [dbo].[items_d365]    Script Date: 30/07/2025 12:27:44 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[items_d365](
	[Old Drug ID] [varchar](50) NULL,
	[Item number] [varchar](50) NULL,
	[Product name] [varchar](254) NULL
) ON [PRIMARY]
GO
/****** Object:  Table [dbo].[VendorProductDescriptionsV2]    Script Date: 30/07/2025 12:27:44 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[VendorProductDescriptionsV2](
	[ItemNumber] [nvarchar](max) NULL,
	[VendorProductNumber] [nvarchar](max) NULL
) ON [PRIMARY] TEXTIMAGE_ON [PRIMARY]
GO
/****** Object:  View [dbo].[vw_ReleasedProductCreationsV2]    Script Date: 30/07/2025 12:27:44 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE VIEW [dbo].[vw_ReleasedProductCreationsV2]
AS
SELECT        dbo.ReleasedProductCreationsV2.ItemNumber, dbo.ReleasedProductCreationsV2.ProductName, dbo.ReleasedProductCreationsV2.PurchaseUnitSymbol, dbo.ReleasedProductCreationsV2.ProductGroupId, 
                         dbo.ReleasedProductCreationsV2.RetailProductCategoryname, dbo.ReleasedProductCreationsV2.BOMUnitSymbol, dbo.ReleasedProductCreationsV2.SearchName, 
                         dbo.ReleasedProductCreationsV2.SalesSalesTaxItemGroupCode, dbo.ReleasedProductCreationsV2.ProductDescription, dbo.ReleasedProductCreationsV2.PurchaseSalesTaxItemGroupCode, 
                         dbo.items_d365.[Old Drug ID] AS Drug_id, dbo.VendorProductDescriptionsV2.VendorProductNumber AS Comments, ISNULL(dbo.vw_ProductSpecificUnitOfMeasureConversions_pcs.Factor, 1) AS Factor, 
                         dbo.ReleasedProductCreationsV2.SalesUnitSymbol
FROM            dbo.ReleasedProductCreationsV2 LEFT OUTER JOIN
                         dbo.vw_ProductSpecificUnitOfMeasureConversions_pcs ON dbo.ReleasedProductCreationsV2.ItemNumber = dbo.vw_ProductSpecificUnitOfMeasureConversions_pcs.ProductNumber LEFT OUTER JOIN
                         dbo.VendorProductDescriptionsV2 ON dbo.ReleasedProductCreationsV2.ItemNumber = dbo.VendorProductDescriptionsV2.ItemNumber LEFT OUTER JOIN
                         dbo.items_d365 ON dbo.ReleasedProductCreationsV2.ItemNumber = dbo.items_d365.[Item number]
WHERE        (dbo.ReleasedProductCreationsV2.ProductGroupId <> N'Service')
GO
/****** Object:  View [dbo].[vw_Product_LEDGERDIMENSION]    Script Date: 30/07/2025 12:27:44 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO

/****** Script for SelectTopNRows command from SSMS  ******/
CREATE VIEW [dbo].[vw_Product_LEDGERDIMENSION]
as
SELECT  p.[ITEM NUMBER]
       ,s.[STORECODE]
	   ,s.[REGION]
       ,s.[DIVISION]
	   ,p.[ITEMGROUP]
	   ,s.[STORECODE] + '-'+ s.[REGION] + '-'+ s.[DIVISION] + '---'+  p.[ITEMGROUP] + '----' DEFAULTLEDGERDIMENSIONDISPLAYVALUE

  FROM [MarinaDynamics365].[dbo].[Mx_Product_Master] p,
  [MarinaDynamics365].[dbo].[Mx_StoreCode] s
GO
/****** Object:  Table [dbo].[Purchase_ReOrder]    Script Date: 30/07/2025 12:27:44 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[Purchase_ReOrder](
	[Item number] [varchar](50) NULL,
	[Product name] [varchar](254) NULL,
	[ReOrder] [int] NULL,
	[Warehouse2] [varchar](50) NULL,
	[Shortname] [varchar](50) NULL,
	[Category] [nvarchar](50) NULL,
	[Brand_Name] [nvarchar](50) NULL,
	[Sub_Category] [nvarchar](50) NULL,
	[Store] [varchar](50) NOT NULL
) ON [PRIMARY]
GO
/****** Object:  View [dbo].[vw_Purchase_ReORder_PIVOT]    Script Date: 30/07/2025 12:27:44 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO



create view [dbo].[vw_Purchase_ReORder_PIVOT]
as

SELECT *
FROM (
    SELECT  [Item number]
        ,[Product name]
	    ,[Category]
        ,[Brand_Name]
		 ,[Sub_Category]
		 ,Store
		  ,[Shortname]
		 , [ReOrder]
    FROM [MarinaDynamics365].[dbo].[Purchase_ReOrder]
) AS SourceTable
PIVOT (
    SUM([ReOrder])
    FOR [Shortname] IN ([800 PARK]	,[800ARJAN]	,[GLDMILE2]	,[800ALQUZ]	,[800CAPTL]	,[800 CENT]	,[800CRCLE]	,[800 DHCC]	,[800 SHJ]	,[800SARAY]	,[800 PH]	,[800ALAIN]	,[800ZAHIA]	,[CARE]	,[CARE 1]	,[CARE 2]	,[GREENS]	,[PALM]	,[SOUTH1]	,[CWALK1]	,[GLDMILE1]	,[ATLANTIS]	,[ATLNTS 2]	,[CENTER]	,[N.SHEBA]	,[OLDTOWN]	,[KHAWANIJ]	,[SHOROOQ]	,[AVENUE]	,[DCCS]	,[BURJ]	,[JUMEIRAH]	,[PROMINAD]	,[ONECNTRL]	,[CARE 3]	,[CARE 5]	,[ARJAN]	,[800RAK]	


)
) AS PivotTable;

GO
/****** Object:  Table [dbo].[Mx_BonusScheme]    Script Date: 30/07/2025 12:27:44 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[Mx_BonusScheme](
	[BonusScheme] [varchar](50) NULL,
	[FromQty] [int] NULL,
	[ToQty] [int] NULL,
	[ToOrder] [int] NULL,
	[Bonus] [int] NULL
) ON [PRIMARY]
GO
/****** Object:  Table [dbo].[Product_BonusScheme]    Script Date: 30/07/2025 12:27:44 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[Product_BonusScheme](
	[ItemNumber] [varchar](50) NULL,
	[BonusScheme] [varchar](50) NULL
) ON [PRIMARY]
GO
/****** Object:  View [dbo].[vw_Product_BonusScheme_Details]    Script Date: 30/07/2025 12:27:44 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE VIEW [dbo].[vw_Product_BonusScheme_Details]
AS
SELECT        dbo.Product_BonusScheme.BonusScheme, dbo.Product_BonusScheme.ItemNumber, dbo.Mx_BonusScheme.FromQty, dbo.Mx_BonusScheme.ToQty, dbo.Mx_BonusScheme.ToOrder, dbo.Mx_BonusScheme.Bonus
FROM            dbo.Product_BonusScheme INNER JOIN
                         dbo.Mx_BonusScheme ON dbo.Product_BonusScheme.BonusScheme = dbo.Mx_BonusScheme.BonusScheme
GO
/****** Object:  UserDefinedFunction [dbo].[GetORderBonus]    Script Date: 30/07/2025 12:27:44 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO


CREATE FUNCTION [dbo].[GetORderBonus] (@ItemNumber varchar(50),@Order int)
RETURNS TABLE
AS
RETURN
(
   SELECT 
      [ToOrder]
      ,[Bonus]
	
  FROM [MarinaDynamics365].[dbo].[vw_Product_BonusScheme_Details]
  where [ItemNumber]=@ItemNumber and isnull(case when @Order between [FromQty] 
  and [ToQty] then toOrder end,0)<>0
)
GO
/****** Object:  View [dbo].[vw_Expiry_Return_Consignment_Policy_items]    Script Date: 30/07/2025 12:27:44 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
--drop view [dbo].[vw_Expiry_Return_Consignment_Policy_items]


create view  [dbo].[vw_Expiry_Return_Consignment_Policy_items]
as

SELECT 
	  e.[Item number],
      e.[Product name],
      e.[Warehouse],
	  s.locationid AS LocationID,
      e.[Batch number],
	    replace(right(convert(varchar, CONVERT(date, dbo.[DateConvertShort_Long](e.[Expiration date])),5),5),'-','') BatchNo_New,

      e.[Location],
      e.[Primary Vendor],
      e.[Vendor Name],
      dbo.[DateConvertShort_Long](e.[Expiration date]) AS [ExpDate],
     CASE WHEN  warehouse  like '%TW' then CAST(e.[Physical inventory] AS FLOAT)
	else 
	CAST(e.[Total available] AS FLOAT) end AS Stock

	  ,	isnull((Select [Return_Trigger_days] from Drug_Manufacturer_Consignment_Policy p 
	  where p.[Manf_id]=e.[Primary Vendor] ),0)  [Return_Trigger_days]
		
		,
			case when datediff(DAY,DATEADD(month, DATEDIFF(month, 0, GETDATE()), 0) , DATEADD(DAY, 1 - DATEPART(DAY, dbo.[DateConvertShort_Long](e.[Expiration date])), dbo.[DateConvertShort_Long](e.[Expiration date])) ) <= 
		 
		
						 isnull( 
	    				(Select [Return_Trigger_days]+30 from Drug_Manufacturer_Consignment_Policy p 
							  where p.[Manf_id]=e.[Primary Vendor] )
										
						
						,0) 
						
						
						then Convert(varchar,datediff(DAY,DATEADD(month, DATEDIFF(month, 0, GETDATE()), 0) ,DATEADD(DAY, 1 - DATEPART(DAY, dbo.[DateConvertShort_Long](e.[Expiration date])), dbo.[DateConvertShort_Long](e.[Expiration date])))) 
						else ''  
			
							end No_Of_Days


		,
			case when datediff(DAY,DATEADD(month, DATEDIFF(month, 0, GETDATE()), 0) , DATEADD(DAY, 1 - DATEPART(DAY, dbo.[DateConvertShort_Long](e.[Expiration date])), dbo.[DateConvertShort_Long](e.[Expiration date])) ) <= 
		 
		
						 isnull( 
	    				(Select [Return_Trigger_days]+30 from Drug_Manufacturer_Consignment_Policy p 
							  where p.[Manf_id]=e.[Primary Vendor] )
										
						
						,0) 
						
						
						then 'Return - ' + Convert(varchar,datediff(DAY,DATEADD(month, DATEDIFF(month, 0, GETDATE()), 0) ,DATEADD(DAY, 1 - DATEPART(DAY, dbo.[DateConvertShort_Long](e.[Expiration date])), dbo.[DateConvertShort_Long](e.[Expiration date])))) +
						' days Before Expry' else ''  
			
							end
		
	
		Remarks
	
 FROM 
      [MarinaDynamics365].[dbo].[Expiry_items_Upload] e
LEFT JOIN 
      [MarinaDynamics365].[dbo].[Mx_StoreCode] s
      ON s.STORECODE = replace(e.[Warehouse],'-TW','')
WHERE 
      CAST(e.[Total available] AS FLOAT) <> 0
	  or CAST(e.[Physical inventory] AS FLOAT)<>0

	  and

  CASE WHEN  warehouse  like '%TW' then CAST(e.[Physical inventory] AS FLOAT)
	else 
	CAST(e.[Total available] AS FLOAT) end >=1 

  and (case when datediff(DAY,DATEADD(month, DATEDIFF(month, 0, GETDATE()), 0) , DATEADD(DAY, 1 - DATEPART(DAY, dbo.[DateConvertShort_Long](e.[Expiration date])), dbo.[DateConvertShort_Long](e.[Expiration date])) ) <= 
		 
		
						 isnull( 
	    				(Select [Return_Trigger_days]+30 from Drug_Manufacturer_Consignment_Policy p 
							  where p.[Manf_id]=e.[Primary Vendor] )
										
						
						,0) 
						
						
						then 'Return - ' + Convert(varchar,datediff(DAY,DATEADD(month, DATEDIFF(month, 0, GETDATE()), 0) ,DATEADD(DAY, 1 - DATEPART(DAY, dbo.[DateConvertShort_Long](e.[Expiration date])), dbo.[DateConvertShort_Long](e.[Expiration date])))) +
						' days Before Expry' else ''  
			
							end
		
)<>''
and
  
  isnull((Select [Return_Trigger_days] from Drug_Manufacturer_Consignment_Policy p 
	  where p.[Manf_id]=e.[Primary Vendor]),0) <>0
GO
/****** Object:  Table [dbo].[Mx_Top100_Items_by_Division]    Script Date: 30/07/2025 12:27:44 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[Mx_Top100_Items_by_Division](
	[ItemNumber] [varchar](50) NULL,
	[ProductName] [varchar](50) NULL,
	[Division] [varchar](50) NULL
) ON [PRIMARY]
GO
/****** Object:  Table [dbo].[MX_Product_MinMax_Price_Vendor_Stock]    Script Date: 30/07/2025 12:27:44 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[MX_Product_MinMax_Price_Vendor_Stock](
	[ItemNumber] [nvarchar](max) NULL,
	[ProductName] [nvarchar](max) NULL,
	[ProductGroupId] [nvarchar](max) NULL,
	[RetailProductCategoryname] [nvarchar](max) NULL,
	[SalesSalesTaxItemGroupCode] [nvarchar](max) NULL,
	[Drug_id] [varchar](50) NULL,
	[STORECODE] [varchar](50) NULL,
	[LocationID] [varchar](50) NULL,
	[ShortName] [varchar](50) NULL,
	[Min] [varchar](50) NOT NULL,
	[Max] [varchar](50) NOT NULL,
	[Cost] [varchar](50) NULL,
	[Price] [varchar](50) NULL,
	[Vendor] [varchar](50) NULL,
	[Stock] [float] NOT NULL,
	[Pending_Stock] [float] NOT NULL,
	[CONS] [money] NOT NULL,
	[TR_Pending] [float] NOT NULL,
	[Unposted_Qty] [numeric](38, 2) NULL,
	[Order_Group] [nvarchar](max) NULL
) ON [PRIMARY] TEXTIMAGE_ON [PRIMARY]
GO
/****** Object:  View [dbo].[vw_FEB2024_MinMax_Order_Branch_Final_ALL_WH_DIVISION]    Script Date: 30/07/2025 12:27:44 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO














create view [dbo].[vw_FEB2024_MinMax_Order_Branch_Final_ALL_WH_DIVISION]
as

SELECT [ItemNumber]
      ,[ProductName]
      ,[ProductGroupId]
      ,[RetailProductCategoryname]
      ,[SalesSalesTaxItemGroupCode]
      ,[Drug_id]
      ,[STORECODE]
      ,[LocationID]
      ,[ShortName]
      ,cast([Min] as int) [Min]
      ,cast([Max] as int) [Max]
      ,[Cost]
      ,[Price]
      ,[Vendor]
      ,floor([Stock]) [Stock]
      ,[Pending_Stock]
	-- , [dbo].[CalCulateOrder]([ItemNumber],[LocationID],(floor([Stock])-floor(Unposted_Qty))+([Pending_Stock]-TR_Pending) ,[Min],[Max]) [Order]
	 -- , [dbo].[CalCulateOrder]([ItemNumber],[LocationID],floor([Stock])+([Pending_Stock]-TR_Pending) ,[Min],[Max]) [Order]
	    , [dbo].[CalCulateOrder_by_Max]([ItemNumber],[LocationID],floor([Stock])+([Pending_Stock]-TR_Pending) ,[Max]) [Order]
	  ,floor(CONS) CONS
	  ,TR_Pending
	  ,Unposted_Qty
	  ,order_group
	  ,isnull((select  'Yes' FROM [MarinaDynamics365].[dbo].[Mx_Top100_Items_by_Division] d 
	  where d.[ItemNumber]=s.ItemNumber AND Division='Hospital'),'No') Hospital
	  ,isnull((select  'Yes' FROM [MarinaDynamics365].[dbo].[Mx_Top100_Items_by_Division] d 
	  where d.[ItemNumber]=s.ItemNumber AND Division='Retail'),'No')  Retail
	  ,isnull((select  'Yes' FROM [MarinaDynamics365].[dbo].[Mx_Top100_Items_by_Division] d 
	  where d.[ItemNumber]=s.ItemNumber AND Division='800'),'No') [800]
  FROM [MarinaDynamics365].[dbo].[MX_Product_MinMax_Price_Vendor_Stock] s
  where  CONS+[Min]+[Max]+[Stock]<>0
  and [STORECODE] not in ('WH0001','WH0002')
  and ItemNumber in (SELECT distinct [ItemNumber]
     
  FROM [MarinaDynamics365].[dbo].[Mx_Top100_Items_by_Division])
GO
/****** Object:  Table [dbo].[Mx_Product_Master_new]    Script Date: 30/07/2025 12:27:44 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[Mx_Product_Master_new](
	[ItemNumber] [nvarchar](max) NULL,
	[ProductName] [nvarchar](max) NULL,
	[PurchaseUnitSymbol] [nvarchar](max) NULL,
	[ProductGroupId] [nvarchar](max) NULL,
	[RetailProductCategoryname] [nvarchar](max) NULL,
	[BOMUnitSymbol] [nvarchar](max) NULL,
	[SearchName] [nvarchar](max) NULL,
	[SalesSalesTaxItemGroupCode] [nvarchar](max) NULL,
	[SalesUnitSymbol] [nvarchar](max) NULL,
	[ProductDescription] [nvarchar](max) NULL,
	[PurchaseSalesTaxItemGroupCode] [nvarchar](max) NULL,
	[Drug_id] [varchar](50) NULL,
	[Factor] [int] NULL,
	[Order_Group] [nvarchar](max) NULL,
	[Comments] [varchar](max) NULL
) ON [PRIMARY] TEXTIMAGE_ON [PRIMARY]
GO
/****** Object:  Table [dbo].[Mx_PriceMaster]    Script Date: 30/07/2025 12:27:44 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[Mx_PriceMaster](
	[Item] [int] NULL,
	[Drug_id] [varchar](50) NULL,
	[DrugName] [nvarchar](max) NULL,
	[Selling_Price] [float] NULL
) ON [PRIMARY] TEXTIMAGE_ON [PRIMARY]
GO
/****** Object:  Table [dbo].[MX_Product_Cost_SPrice_Upload_Raw]    Script Date: 30/07/2025 12:27:44 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[MX_Product_Cost_SPrice_Upload_Raw](
	[Item number] [varchar](50) NULL,
	[Product name] [varchar](254) NULL,
	[Price] [varchar](50) NULL,
	[Item sales tax group] [varchar](50) NULL,
	[Price2] [varchar](50) NULL,
	[Vendor] [varchar](50) NULL
) ON [PRIMARY]
GO
/****** Object:  Table [dbo].[VendorsV2]    Script Date: 30/07/2025 12:27:44 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[VendorsV2](
	[dataAreaId] [nvarchar](max) NULL,
	[VendorAccountNumber] [nvarchar](max) NULL,
	[OIDNomineeDetails] [nvarchar](max) NULL,
	[PaymentFeeGroupId] [nvarchar](max) NULL,
	[AddressRecordId] [bigint] NULL,
	[PaymentId] [nvarchar](max) NULL,
	[VendorInvoiceDeclarationId] [nvarchar](max) NULL,
	[AddressStateId] [nvarchar](max) NULL,
	[DefaultPaymentDayName] [nvarchar](max) NULL,
	[AddressDescription] [nvarchar](max) NULL,
	[TaxOperationCode] [nvarchar](max) NULL,
	[PurchaseWorkCalendarId] [nvarchar](max) NULL,
	[AddressBooks] [nvarchar](max) NULL,
	[PersonBirthYear] [bigint] NULL,
	[VendorExceptionGroupId] [nvarchar](max) NULL,
	[IsMinorityOwned] [nvarchar](max) NULL,
	[AddressCity] [nvarchar](max) NULL,
	[DefaultPurchaseOrderPoolId] [nvarchar](max) NULL,
	[IsChangeMangementOverrideByVendorAllowed] [nvarchar](max) NULL,
	[StructureDepartment] [nvarchar](max) NULL,
	[AddressLatitude] [float] NULL,
	[PricePointRoundingType] [nvarchar](max) NULL,
	[IsVendorLocatedInHUBZone] [nvarchar](max) NULL,
	[AddressZipCode] [nvarchar](max) NULL,
	[PANReferenceNumber] [nvarchar](max) NULL,
	[MainContactPersonnelNumber] [nvarchar](max) NULL,
	[PersonMiddleName] [nvarchar](max) NULL,
	[SiretNumber] [nvarchar](max) NULL,
	[IsIncomingFiscalDocumentGenerated] [nvarchar](max) NULL,
	[ServiceCategory] [nvarchar](max) NULL,
	[PersonPersonalSuffix] [nvarchar](max) NULL,
	[IsSubcontractor] [nvarchar](max) NULL,
	[AddressBrazilianIE] [nvarchar](max) NULL,
	[PersonAnniversaryDay] [bigint] NULL,
	[IsW9Received] [nvarchar](max) NULL,
	[FiscalDocumentIncomeCode] [nvarchar](max) NULL,
	[VendorPaymentFineCode] [nvarchar](max) NULL,
	[PurchaseOrderConsolidationDayOfMonth] [bigint] NULL,
	[CUSIPIdentificationNumber] [nvarchar](max) NULL,
	[AddressBuildingCompliment] [nvarchar](max) NULL,
	[PersonProfessionalTitle] [nvarchar](max) NULL,
	[BusinessSegmentCode] [nvarchar](max) NULL,
	[PrimaryFacebookDescription] [nvarchar](max) NULL,
	[DefaultTotalDiscountVendorGroupCode] [nvarchar](max) NULL,
	[DefaultDeliveryModeId] [nvarchar](max) NULL,
	[PrimaryPhoneNumber] [nvarchar](max) NULL,
	[AddressLocationId] [nvarchar](max) NULL,
	[Notes] [nvarchar](max) NULL,
	[PrimaryURLPurpose] [nvarchar](max) NULL,
	[PurchaseShipCalendarId] [nvarchar](max) NULL,
	[AddressPostBox] [nvarchar](max) NULL,
	[NumberSequenceGroupId] [nvarchar](max) NULL,
	[ForeignVendor] [nvarchar](max) NULL,
	[IsServiceVeteranOwned] [nvarchar](max) NULL,
	[PrimaryTelexPurpose] [nvarchar](max) NULL,
	[BrazilianCCM] [nvarchar](max) NULL,
	[PrimaryTelexDescription] [nvarchar](max) NULL,
	[CISStatus] [nvarchar](max) NULL,
	[VendorInvoiceLineMatchingPolicy] [nvarchar](max) NULL,
	[VendorPriceToleranceGroupId] [nvarchar](max) NULL,
	[IsICMSContributor] [nvarchar](max) NULL,
	[LineOfBusinessId] [nvarchar](max) NULL,
	[CompositionScheme] [nvarchar](max) NULL,
	[Tax1099NameToUse] [nvarchar](max) NULL,
	[PrimaryFaxNumberExtension] [nvarchar](max) NULL,
	[SeparateDivisionId] [nvarchar](max) NULL,
	[Tax1099Type] [nvarchar](max) NULL,
	[TCSGroup] [nvarchar](max) NULL,
	[PersonAnniversaryMonth] [nvarchar](max) NULL,
	[SalesPriceRounding] [nvarchar](max) NULL,
	[BankOrderOfPayment] [nvarchar](max) NULL,
	[MultilineDiscountVendorGroupCode] [nvarchar](max) NULL,
	[AddressStreet] [nvarchar](max) NULL,
	[ExchangeRate] [float] NULL,
	[PurchaseRebateVendorGroupId] [nvarchar](max) NULL,
	[IsSmallBusiness] [nvarchar](max) NULL,
	[ResidenceForeignCountryRegionId] [nvarchar](max) NULL,
	[CompanyChainName] [nvarchar](max) NULL,
	[PersonGender] [nvarchar](max) NULL,
	[IsVendorPayingBankPaymentFee] [nvarchar](max) NULL,
	[ChargeVendorGroupId] [nvarchar](max) NULL,
	[ZakatServiceType] [nvarchar](max) NULL,
	[PrimaryFaxNumberDescription] [nvarchar](max) NULL,
	[AddressValidTo] [datetime2](0) NULL,
	[IsVendorLocallyOwned] [nvarchar](max) NULL,
	[DefaultInventoryStatusId] [nvarchar](max) NULL,
	[PrimaryContactURLRecordId] [bigint] NULL,
	[AddressCountyId] [nvarchar](max) NULL,
	[PrimaryEmailAddressPurpose] [nvarchar](max) NULL,
	[CommercialRegisterInsetNumber] [nvarchar](max) NULL,
	[PrimaryPhoneNumberDescription] [nvarchar](max) NULL,
	[DefaultOffsetAccountType] [nvarchar](max) NULL,
	[FiscalOperationPresenceType] [nvarchar](max) NULL,
	[VendorPaymentFinancialInterestCode] [nvarchar](max) NULL,
	[DestinationCode] [nvarchar](max) NULL,
	[PersonInitials] [nvarchar](max) NULL,
	[PersonMaritalStatus] [nvarchar](max) NULL,
	[VendorType] [nvarchar](max) NULL,
	[PrimaryLinkedInDescription] [nvarchar](max) NULL,
	[LanguageId] [nvarchar](max) NULL,
	[ForeignerId] [nvarchar](max) NULL,
	[ZakatFileNumber] [nvarchar](max) NULL,
	[AddressTimeZone] [nvarchar](max) NULL,
	[ForeignVendorTaxRegistrationId] [nvarchar](max) NULL,
	[AddressCountryRegionId] [nvarchar](max) NULL,
	[CommercialRegisterName] [nvarchar](max) NULL,
	[ZakatRegistrationNumber] [nvarchar](max) NULL,
	[RFCFederalTaxNumber] [nvarchar](max) NULL,
	[CUSIPDetails] [nvarchar](max) NULL,
	[PaymentTransactionCode] [nvarchar](max) NULL,
	[OurAccountNumber] [nvarchar](max) NULL,
	[IsPurchaseOrderChangeRequestOverrideAllowed] [nvarchar](max) NULL,
	[FormattedPrimaryAddress] [nvarchar](max) NULL,
	[Tax1099BoxId] [nvarchar](max) NULL,
	[PrimaryFacebookPurpose] [nvarchar](max) NULL,
	[CISCompanyRegistrationNumber] [nvarchar](max) NULL,
	[PrimaryContactEmailRecordId] [bigint] NULL,
	[FiscalCode] [nvarchar](max) NULL,
	[DefaultDeliveryTermsCode] [nvarchar](max) NULL,
	[ColorIdPrefix] [nvarchar](max) NULL,
	[BusinessSubsegmentCode] [nvarchar](max) NULL,
	[OrganizationABCCode] [nvarchar](max) NULL,
	[CreditLimit] [float] NULL,
	[CISUniqueTaxPayerReference] [nvarchar](max) NULL,
	[PrimaryTelex] [nvarchar](max) NULL,
	[PrimaryContactPhoneRecordId] [bigint] NULL,
	[HasOnlyTakenBids] [nvarchar](max) NULL,
	[CISVerificationDate] [datetime2](0) NULL,
	[PrimaryURLDescription] [nvarchar](max) NULL,
	[TaxExemptNumber] [nvarchar](max) NULL,
	[PrimaryLinkedInPurpose] [nvarchar](max) NULL,
	[BrazilianINSSCEI] [nvarchar](max) NULL,
	[VendorGroupId] [nvarchar](max) NULL,
	[OIDInvestorType] [nvarchar](max) NULL,
	[PrimaryFaxNumberPurpose] [nvarchar](max) NULL,
	[PersonChildrenNames] [nvarchar](max) NULL,
	[AddressCountryRegionISOCode] [nvarchar](max) NULL,
	[BuyerGroupId] [nvarchar](max) NULL,
	[BankAccountId] [nvarchar](max) NULL,
	[UniquePopulationRegistryCode] [nvarchar](max) NULL,
	[FactoringVendorAccountNumber] [nvarchar](max) NULL,
	[CashDiscountCode] [nvarchar](max) NULL,
	[VendorPartyType] [nvarchar](max) NULL,
	[AddressStreetInKana] [nvarchar](max) NULL,
	[IsPrimaryPhoneNumberMobile] [nvarchar](max) NULL,
	[PersonPhoneticFirstName] [nvarchar](max) NULL,
	[CISVerificationNumber] [nvarchar](max) NULL,
	[PersonAnniversaryYear] [bigint] NULL,
	[TDSGroup] [nvarchar](max) NULL,
	[PersonProfessionalSuffix] [nvarchar](max) NULL,
	[DefaultPaymentScheduleName] [nvarchar](max) NULL,
	[CurrencyCode] [nvarchar](max) NULL,
	[PersonBirthMonth] [nvarchar](max) NULL,
	[NatureOfAssessee] [nvarchar](max) NULL,
	[PrimaryPhoneNumberExtension] [nvarchar](max) NULL,
	[NAFCode] [nvarchar](max) NULL,
	[VendorProductHierarchyId] [bigint] NULL,
	[ArePricesIncludingSalesTax] [nvarchar](max) NULL,
	[DefaultOffsetLedgerAccountDisplayValue] [nvarchar](max) NULL,
	[NationalRegistryNumberId] [nvarchar](max) NULL,
	[CentralBankPurposeText] [nvarchar](max) NULL,
	[RoundingMethod] [nvarchar](max) NULL,
	[AddressValidFrom] [datetime2](0) NULL,
	[SizeIdPrefix] [nvarchar](max) NULL,
	[VendorOrganizationName] [nvarchar](max) NULL,
	[PersonFirstName] [nvarchar](max) NULL,
	[DefaultPaymentTermsName] [nvarchar](max) NULL,
	[Tax1099IdType] [nvarchar](max) NULL,
	[OrganizationEmployeeAmount] [bigint] NULL,
	[PrimaryTwitterDescription] [nvarchar](max) NULL,
	[PrimaryEmailAddressDescription] [nvarchar](max) NULL,
	[PersonHobbies] [nvarchar](max) NULL,
	[VendorPortalCollaborationMethod] [nvarchar](max) NULL,
	[InvoiceVendorAccountNumber] [nvarchar](max) NULL,
	[WillPurchaseOrderIncludePricesAndAmounts] [nvarchar](max) NULL,
	[OverrideSalesTax] [nvarchar](max) NULL,
	[BarcodeNumberSequence] [nvarchar](max) NULL,
	[AddressDistrictName] [nvarchar](max) NULL,
	[SSIValidityDate] [datetime2](0) NULL,
	[CommercialRegisterSection] [nvarchar](max) NULL,
	[ProductDescriptionVendorGroupId] [nvarchar](max) NULL,
	[TaxPartnerKind] [nvarchar](max) NULL,
	[ForeignResident] [nvarchar](max) NULL,
	[BankTransactionType] [nvarchar](max) NULL,
	[AddressBrazilianCNPJOrCPF] [nvarchar](max) NULL,
	[AddressLocationRoles] [nvarchar](max) NULL,
	[ISNationalRegistryNumber] [nvarchar](max) NULL,
	[PrimaryEmailAddress] [nvarchar](max) NULL,
	[NameControl] [nvarchar](max) NULL,
	[Nationality] [nvarchar](max) NULL,
	[DefaultProcumentWarehouseId] [nvarchar](max) NULL,
	[PrimaryPhoneNumberPurpose] [nvarchar](max) NULL,
	[SalesTaxGroupCode] [nvarchar](max) NULL,
	[CompanyType] [nvarchar](max) NULL,
	[DIOTCountryCode] [nvarchar](max) NULL,
	[DefaultSupplementaryProductVendorGroupId] [nvarchar](max) NULL,
	[PrimaryContactPersonId] [nvarchar](max) NULL,
	[AddressStreetNumber] [nvarchar](max) NULL,
	[DIOTVendorType] [nvarchar](max) NULL,
	[PersonPersonalTitle] [nvarchar](max) NULL,
	[PrimaryTwitterPurpose] [nvarchar](max) NULL,
	[DIOTOperationType] [nvarchar](max) NULL,
	[BrazilianCNAE] [nvarchar](max) NULL,
	[PrimaryLinkedIn] [nvarchar](max) NULL,
	[CreditRating] [nvarchar](max) NULL,
	[DUNSNumber] [nvarchar](max) NULL,
	[PersonLastName] [nvarchar](max) NULL,
	[IsOwnerDisabled] [nvarchar](max) NULL,
	[OnHoldStatus] [nvarchar](max) NULL,
	[EnterpriseNumber] [nvarchar](max) NULL,
	[IsFlaggedWithSecondTIN] [nvarchar](max) NULL,
	[InventoryProfileType] [nvarchar](max) NULL,
	[VendorKnownAsName] [nvarchar](max) NULL,
	[SSIVendor] [nvarchar](max) NULL,
	[IsForeignEntity] [nvarchar](max) NULL,
	[OrganizationPhoneticName] [nvarchar](max) NULL,
	[PANNumber] [nvarchar](max) NULL,
	[PaymentSpecificationId] [nvarchar](max) NULL,
	[TaxAgent] [nvarchar](max) NULL,
	[BirthPlace] [nvarchar](max) NULL,
	[PricePointGroupId] [nvarchar](max) NULL,
	[IsGSTCompositionSchemeEnabled] [nvarchar](max) NULL,
	[DefaultVendorPaymentMethodName] [nvarchar](max) NULL,
	[PrimaryURL] [nvarchar](max) NULL,
	[CISNationalInsuranceNumber] [nvarchar](max) NULL,
	[VendorHoldReleaseDate] [datetime2](0) NULL,
	[VendorSearchName] [nvarchar](max) NULL,
	[DefaultLedgerDimensionDisplayValue] [nvarchar](max) NULL,
	[BirthCountyCode] [nvarchar](max) NULL,
	[Tax1099DoingBusinessAsName] [nvarchar](max) NULL,
	[IsReportingTax1099] [nvarchar](max) NULL,
	[PersonBirthDay] [bigint] NULL,
	[InventoryProfile] [nvarchar](max) NULL,
	[PreferentialVendor] [nvarchar](max) NULL,
	[DefaultPurchaseSiteId] [nvarchar](max) NULL,
	[StyleIdPrefix] [nvarchar](max) NULL,
	[PrimaryFacebook] [nvarchar](max) NULL,
	[AddressLongitude] [float] NULL,
	[PriceVendorGroupId] [nvarchar](max) NULL,
	[AddressCityInKana] [nvarchar](max) NULL,
	[ClearingPeriodPaymentTermsId] [nvarchar](max) NULL,
	[PersonLastNamePrefix] [nvarchar](max) NULL,
	[CentralBankPurposeCode] [nvarchar](max) NULL,
	[OrganizationNumber] [nvarchar](max) NULL,
	[BrazilianIE] [nvarchar](max) NULL,
	[DefaultCashDiscountUsage] [nvarchar](max) NULL,
	[IsOneTimeVendor] [nvarchar](max) NULL,
	[IsW9CheckingEnabled] [nvarchar](max) NULL,
	[PersonPhoneticMiddleName] [nvarchar](max) NULL,
	[WillReceiptsListProcessingSummaryUpdatePurchaseOrder] [nvarchar](max) NULL,
	[StateInscription] [nvarchar](max) NULL,
	[PANStatus] [nvarchar](max) NULL,
	[IsWomanOwner] [nvarchar](max) NULL,
	[PrimaryContactFaxRecordId] [bigint] NULL,
	[PrimaryTwitter] [nvarchar](max) NULL,
	[VendorPartyNumber] [nvarchar](max) NULL,
	[WillPurchaseOrderProcessingSummaryUpdatePurchaseOrder] [nvarchar](max) NULL,
	[BrazilianCNPJOrCPF] [nvarchar](max) NULL,
	[BrazilianNIT] [nvarchar](max) NULL,
	[IsPrimaryEmailAddressIMEnabled] [nvarchar](max) NULL,
	[CreateBarcodeIfNeeded] [nvarchar](max) NULL,
	[PrimaryFaxNumber] [nvarchar](max) NULL,
	[WillProductReceiptProcessingSummaryUpdatePurchaseOrder] [nvarchar](max) NULL,
	[IsWithholdingTaxCalculated] [nvarchar](max) NULL,
	[PersonPhoneticLastName] [nvarchar](max) NULL,
	[IsServiceDeliveryAddressBased] [nvarchar](max) NULL,
	[WillInvoiceProcessingSummaryUpdatePurchaseOrder] [nvarchar](max) NULL,
	[IsPurchaseConsumed] [nvarchar](max) NULL,
	[IsCUSIPIdentificationNumberApplicable] [nvarchar](max) NULL,
	[GTAVendor] [nvarchar](max) NULL,
	[LineDiscountVendorGroupCode] [nvarchar](max) NULL,
	[WithholdingTaxGroupCode] [nvarchar](max) NULL,
	[Tax1099FederalTaxId] [nvarchar](max) NULL,
	[UPSFreightZone] [nvarchar](max) NULL,
	[EthnicOriginId] [nvarchar](max) NULL,
	[VendorDUNSNumber] [nvarchar](max) NULL,
	[WithholdingTaxVendorType] [nvarchar](max) NULL,
	[ElectronicLocationId] [nvarchar](max) NULL,
	[FixedExchangeRate] [nvarchar](max) NULL,
	[IsChangeManagementActivated] [nvarchar](max) NULL,
	[IsTaxationOverPayroll_BR] [nvarchar](max) NULL,
	[IsPublicSector_IT] [nvarchar](max) NULL,
	[DefaultAgentVendorAccountNumber] [nvarchar](max) NULL,
	[VendorOverUnderdeliveryToleranceGroupId] [nvarchar](max) NULL,
	[IsTransportationServicesProvider] [nvarchar](max) NULL,
	[ShippingVendorType] [nvarchar](max) NULL,
	[VendorCostTypeGroup] [nvarchar](max) NULL,
	[DefaultFromShippingPortId] [nvarchar](max) NULL,
	[IsImportCostingVendor] [nvarchar](max) NULL,
	[ShippingVendorAccountNumber] [nvarchar](max) NULL
) ON [PRIMARY] TEXTIMAGE_ON [PRIMARY]
GO
/****** Object:  View [dbo].[Vw_Mx_Product_Cost_SP_Agent]    Script Date: 30/07/2025 12:27:44 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE VIEW [dbo].[Vw_Mx_Product_Cost_SP_Agent]
AS
SELECT        dbo.MX_Product_Cost_SPrice_Upload_Raw.[Item number], dbo.Mx_Product_Master_new.ProductName AS [Product Name], dbo.MX_Product_Cost_SPrice_Upload_Raw.[Item sales tax group], 
                         dbo.MX_Product_Cost_SPrice_Upload_Raw.Price2 AS UnitCost, dbo.VendorsV2.VendorOrganizationName AS Agent, dbo.MX_Product_Cost_SPrice_Upload_Raw.Vendor, ISNULL(dbo.Mx_PriceMaster.Selling_Price, '0') 
                         AS SP
FROM            dbo.MX_Product_Cost_SPrice_Upload_Raw LEFT OUTER JOIN
                         dbo.Mx_PriceMaster ON dbo.MX_Product_Cost_SPrice_Upload_Raw.[Item number] = dbo.Mx_PriceMaster.Item LEFT OUTER JOIN
                         dbo.Mx_Product_Master_new ON dbo.MX_Product_Cost_SPrice_Upload_Raw.[Item number] = dbo.Mx_Product_Master_new.ItemNumber LEFT OUTER JOIN
                         dbo.VendorsV2 ON dbo.MX_Product_Cost_SPrice_Upload_Raw.Vendor = dbo.VendorsV2.VendorAccountNumber
GO
/****** Object:  View [dbo].[D365_vw_Mx_Product_Cat_SP_Cost_Agent]    Script Date: 30/07/2025 12:27:44 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE VIEW [dbo].[D365_vw_Mx_Product_Cat_SP_Cost_Agent]
AS
SELECT        dbo.Mx_Product_Master_new.ItemNumber, dbo.Mx_Product_Master_new.ProductName, dbo.Mx_Product_Master_new.ProductGroupId, dbo.Mx_Product_Master_new.RetailProductCategoryname, 
                         dbo.Mx_Product_Master_new.PurchaseSalesTaxItemGroupCode, dbo.Mx_Product_Master_new.Drug_id, dbo.Vw_Mx_Product_Cost_SP_Agent.SP, dbo.Vw_Mx_Product_Cost_SP_Agent.[Item sales tax group], 
                         dbo.Vw_Mx_Product_Cost_SP_Agent.UnitCost, dbo.Vw_Mx_Product_Cost_SP_Agent.Vendor, dbo.Vw_Mx_Product_Cost_SP_Agent.Agent, dbo.Vw_Mx_Product_Cost_SP_Agent.SP AS Expr1
FROM            dbo.Mx_Product_Master_new LEFT OUTER JOIN
                         dbo.Vw_Mx_Product_Cost_SP_Agent ON dbo.Mx_Product_Master_new.ItemNumber = dbo.Vw_Mx_Product_Cost_SP_Agent.[Item number]
WHERE        (NOT (dbo.Mx_Product_Master_new.ItemNumber LIKE N'SERV_%')) AND (dbo.Mx_Product_Master_new.ItemNumber <> N'GIFTCARD')
GO
/****** Object:  View [dbo].[vw_FEB2024_MinMax_RE_Order_Branch_Final_max]    Script Date: 30/07/2025 12:27:44 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO





















create view [dbo].[vw_FEB2024_MinMax_RE_Order_Branch_Final_max]
as

SELECT [ItemNumber]
      ,[ProductName]
      ,[ProductGroupId]
      ,[RetailProductCategoryname]
      ,[SalesSalesTaxItemGroupCode]
      ,[Drug_id]
      ,[STORECODE]
      ,[LocationID]
      ,[ShortName]
      ,cast([Min] as int) [Min]
      ,cast([Max] as int) [Max]
      ,[Cost]
      ,[Price]
      ,[Vendor]
      ,floor([Stock]) [Stock]
      ,[Pending_Stock]
	-- , [dbo].[CalCulateOrder]([ItemNumber],[LocationID],(floor([Stock])-floor(Unposted_Qty)) +Ordered+[Pending_Stock],[Min],[Max]) [Order]
	  , [dbo].[CalCulateOrder_max]([ItemNumber],[LocationID],floor([Stock_after_Unposted]) +Ordered,[Min],[Max]) [Order]
 --, [dbo].[CalCulateOrder]([ItemNumber],[LocationID],floor([Stock]) +Ordered+[Pending_Stock],[Min],[Max]) [Order]
	  ,floor(CONS) CONS
	   ,(Select Sno from REORDER_Branch_hierarchy h
	  where h.[STORECODE]=f.[STORECODE]  ) turn
	 ,isnull((SELECT 
								    [Stock]
									FROM [MarinaDynamics365].[dbo].Drug_Batch_Stock_ordered_SUM_STORE s
									where s.[ItemNumber]=f.[ItemNumber] ),0) Store_Stock

	  ,(SELECT [Old Category]
     
  FROM [MarinaDynamics365].[dbo].[Mx_Product_Category_v2] m
  where m.[Item number]=f.ItemNumber) Category
	  ,Ordered
	  ,Unposted_Qty
	,  Qty_Unposted
	  ,floor(Stock_after_Unposted) Stock_after_Unposted
  FROM [MarinaDynamics365].[dbo].MX_Product_MinMax_Price_Vendor_Stock_re_order f
  where  CONS+[Min]+[Max]+[Stock]<>0
  and [STORECODE] not in ('WH0001','WH0002')
  and [STORECODE] in (Select [STORECODE]  FROM [MarinaDynamics365].[dbo].[REORDER_Branch_hierarchy])
  and WAREHOUSE='MARINA'
GO
/****** Object:  Table [dbo].[ProductMaster_Upload_price]    Script Date: 30/07/2025 12:27:44 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[ProductMaster_Upload_price](
	[Product Id] [varchar](50) NULL,
	[Retail Price] [varchar](50) NULL
) ON [PRIMARY]
GO
/****** Object:  View [dbo].[vw_Mx_PriceMaster_old]    Script Date: 30/07/2025 12:27:44 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO

CREATE VIEW [dbo].[vw_Mx_PriceMaster_old]
AS
SELECT        dbo.ProductMaster_Upload_price.[Product Id] AS Item, dbo.Mx_Product_Master.Drug_ID, dbo.Mx_Product_Master.DrugName, dbo.ProductMaster_Upload_price.[Retail Price] AS Selling_Price
FROM            dbo.ProductMaster_Upload_price LEFT OUTER JOIN
                         dbo.Mx_Product_Master ON dbo.ProductMaster_Upload_price.[Product Id] = dbo.Mx_Product_Master.[Item number]
WHERE        (NOT (dbo.ProductMaster_Upload_price.[Product Id] IN ('114314', '114315', '114640', '115382')))
GO
/****** Object:  Table [dbo].[TransferOrderHeaders]    Script Date: 30/07/2025 12:27:44 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[TransferOrderHeaders](
	[TransferOrderNumber] [nvarchar](max) NULL,
	[RequestedReceiptDate] [datetime2](0) NULL,
	[ShippingWarehouseId] [nvarchar](max) NULL,
	[ReceivingWarehouseId] [nvarchar](max) NULL,
	[ShippingAddressName] [nvarchar](max) NULL,
	[TransferOrderStatus] [nvarchar](max) NULL,
	[ReceivingAddressName] [nvarchar](max) NULL,
	[RequestedShippingDate] [datetime2](0) NULL
) ON [PRIMARY] TEXTIMAGE_ON [PRIMARY]
GO
/****** Object:  Table [dbo].[TransferOrderLines_Upload_Raw]    Script Date: 30/07/2025 12:27:44 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[TransferOrderLines_Upload_Raw](
	[Item number] [varchar](50) NULL,
	[Physical date] [varchar](50) NULL,
	[Financial date] [varchar](50) NULL,
	[Reference] [varchar](50) NULL,
	[Number] [varchar](50) NULL,
	[Receipt] [varchar](50) NULL,
	[Issue] [varchar](50) NULL,
	[Quantity] [varchar](50) NULL,
	[Unit] [varchar](50) NULL,
	[CW quantity] [varchar](50) NULL,
	[CW unit] [varchar](50) NULL,
	[Cost amount] [varchar](50) NULL,
	[Batch number] [varchar](50) NULL
) ON [PRIMARY]
GO
/****** Object:  View [dbo].[vw_TransferOrderLines_Pending_WH_Upload]    Script Date: 30/07/2025 12:27:44 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE VIEW [dbo].[vw_TransferOrderLines_Pending_WH_Upload]
AS
SELECT        dbo.TransferOrderLines_Upload_Raw.Number, dbo.TransferOrderLines_Upload_Raw.Quantity, dbo.TransferOrderHeaders.TransferOrderStatus, dbo.TransferOrderHeaders.ShippingWarehouseId, 
                         dbo.TransferOrderLines_Upload_Raw.[Item number], dbo.TransferOrderHeaders.RequestedReceiptDate, dbo.Mx_Product_Master_new.ProductName, dbo.Mx_Product_Master_new.ProductGroupId, 
                         CASE WHEN dbo.TransferOrderHeaders.[ShippingWarehouseId] = 'WH0001' THEN 1 WHEN dbo.TransferOrderHeaders.[ShippingWarehouseId] = 'WH0002' THEN 8 END AS WH
FROM            dbo.TransferOrderLines_Upload_Raw LEFT OUTER JOIN
                         dbo.TransferOrderHeaders ON dbo.TransferOrderLines_Upload_Raw.Number = dbo.TransferOrderHeaders.TransferOrderNumber LEFT OUTER JOIN
                         dbo.Mx_Product_Master_new ON dbo.TransferOrderLines_Upload_Raw.[Item number] = dbo.Mx_Product_Master_new.ItemNumber
GO
/****** Object:  Table [dbo].[Branch_Replenishment_Cons_Sum_Total]    Script Date: 30/07/2025 12:27:44 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[Branch_Replenishment_Cons_Sum_Total](
	[ItemNumber] [nchar](10) NULL,
	[Qty_Sold] [money] NULL
) ON [PRIMARY]
GO
/****** Object:  Table [dbo].[Drug_Batch_Stock_ordered_SUM_Branch_Total]    Script Date: 30/07/2025 12:27:44 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[Drug_Batch_Stock_ordered_SUM_Branch_Total](
	[ItemNumber] [nvarchar](max) NULL,
	[Stock] [float] NULL,
	[Ordered] [float] NULL
) ON [PRIMARY] TEXTIMAGE_ON [PRIMARY]
GO
/****** Object:  Table [dbo].[Drug_Batch_Stock_ordered_SUM_PUR_WH]    Script Date: 30/07/2025 12:27:44 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[Drug_Batch_Stock_ordered_SUM_PUR_WH](
	[ItemNumber] [nvarchar](max) NULL,
	[Stock] [float] NULL,
	[Ordered] [float] NULL
) ON [PRIMARY] TEXTIMAGE_ON [PRIMARY]
GO
/****** Object:  View [dbo].[vw_Branch_Replenisment_final_view_Order]    Script Date: 30/07/2025 12:27:44 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO

    CREATE VIEW [dbo].[vw_Branch_Replenisment_final_view_Order] AS
   SELECT        dbo.Mx_Product_Master_new.ItemNumber, dbo.Mx_Product_Master_new.ProductName, ISNULL(dbo.Drug_Batch_Stock_ordered_SUM_Branch_Total.Stock, 0) AS Stock, 
                         ISNULL(dbo.Drug_Batch_Stock_ordered_SUM_Branch_Total.Ordered, 0) AS InTransit, ISNULL(dbo.Branch_Replenishment_Cons_Sum_Total.Qty_Sold, 0) AS Cons, ISNULL(dbo.Drug_Batch_Stock_ordered_SUM_PUR_WH.Stock, 
                         0) AS WH_Stock, ISNULL(dbo.Drug_Batch_Stock_ordered_SUM_PUR_WH.Ordered, 0) AS WH_InTransit, ISNULL(dbo.Drug_Batch_Stock_ordered_SUM_Branch_Total.Stock, 0) 
                         + ISNULL(dbo.Drug_Batch_Stock_ordered_SUM_Branch_Total.Ordered, 0) + ISNULL(dbo.Drug_Batch_Stock_ordered_SUM_PUR_WH.Stock, 0) + ISNULL(dbo.Drug_Batch_Stock_ordered_SUM_PUR_WH.Ordered, 0) 
                         AS Total_Stock, ISNULL(dbo.Branch_Replenishment_Cons_Sum_Total.Qty_Sold, 0) / 30 * 90  - (ISNULL(dbo.Drug_Batch_Stock_ordered_SUM_Branch_Total.Stock, 0) 
                         + ISNULL(dbo.Drug_Batch_Stock_ordered_SUM_Branch_Total.Ordered, 0) + ISNULL(dbo.Drug_Batch_Stock_ordered_SUM_PUR_WH.Stock, 0) + ISNULL(dbo.Drug_Batch_Stock_ordered_SUM_PUR_WH.Ordered, 0)) 
                         AS Req_Order, dbo.Mx_PriceMaster.Selling_Price, ISNULL(dbo.VendorsV2.VendorOrganizationName, N'NO VENDOR ASSIGNED') AS Vendor
						 ,30 as Sales_Days
						 ,90 as Req_Days
FROM            dbo.VendorsV2 INNER JOIN
                         dbo.MX_Product_Cost_SPrice_Upload_Raw ON dbo.VendorsV2.VendorAccountNumber = dbo.MX_Product_Cost_SPrice_Upload_Raw.Vendor RIGHT OUTER JOIN
                         dbo.Mx_Product_Master_new ON dbo.MX_Product_Cost_SPrice_Upload_Raw.[Item number] = dbo.Mx_Product_Master_new.ItemNumber LEFT OUTER JOIN
                         dbo.Mx_PriceMaster ON dbo.Mx_Product_Master_new.ItemNumber = dbo.Mx_PriceMaster.Item LEFT OUTER JOIN
                         dbo.Drug_Batch_Stock_ordered_SUM_PUR_WH ON dbo.Mx_Product_Master_new.ItemNumber = dbo.Drug_Batch_Stock_ordered_SUM_PUR_WH.ItemNumber LEFT OUTER JOIN
                         dbo.Branch_Replenishment_Cons_Sum_Total ON dbo.Mx_Product_Master_new.ItemNumber = dbo.Branch_Replenishment_Cons_Sum_Total.ItemNumber LEFT OUTER JOIN
                         dbo.Drug_Batch_Stock_ordered_SUM_Branch_Total ON dbo.Mx_Product_Master_new.ItemNumber = dbo.Drug_Batch_Stock_ordered_SUM_Branch_Total.ItemNumber

    
GO
/****** Object:  Table [dbo].[PostdatedChecks]    Script Date: 30/07/2025 12:27:44 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[PostdatedChecks](
	[dataAreaId] [varchar](255) NULL,
	[JournalBatchNumber] [varchar](255) NULL,
	[LineNumber] [int] NULL,
	[CreditAmount] [int] NULL,
	[AccountDisplayValue] [varchar](255) NULL,
	[IsPaymentStopped] [varchar](255) NULL,
	[PostDatedCheckStatus] [varchar](255) NULL,
	[CurrencyCode] [varchar](255) NULL,
	[IsReplacementCheck] [varchar](255) NULL,
	[TransactionDate] [varchar](255) NULL,
	[DebitAmount] [float] NULL,
	[Voucher] [varchar](255) NULL,
	[AccountType] [varchar](255) NULL,
	[CheckNumber] [varchar](255) NULL,
	[MaturityDate] [varchar](255) NULL,
	[LastUpdate] [datetime] NULL
) ON [PRIMARY]
GO
/****** Object:  Table [dbo].[VendorPaymentJournalLines]    Script Date: 30/07/2025 12:27:44 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[VendorPaymentJournalLines](
	[dataAreaId] [nvarchar](max) NULL,
	[JournalBatchNumber] [nvarchar](max) NULL,
	[LineNumber] [float] NULL,
	[AccountDisplayValue] [nvarchar](max) NULL,
	[PaymentId] [nvarchar](max) NULL,
	[PostdatedCheckCashierDisplayValue] [nvarchar](max) NULL,
	[UseSalesTaxDirectionFromMainAccount] [nvarchar](max) NULL,
	[NACHAIATOFACSecondaryScreeningIndicator] [nvarchar](max) NULL,
	[VendorName] [nvarchar](max) NULL,
	[OffsetFinTagDisplayValue] [nvarchar](max) NULL,
	[TransactionDate] [datetime2](0) NULL,
	[PostingProfile] [nvarchar](max) NULL,
	[ReportingCurrencyExchRateSecondary] [float] NULL,
	[ReportingCurrencyExchRate] [float] NULL,
	[AccountType] [nvarchar](max) NULL,
	[TransactionText] [nvarchar](max) NULL,
	[RemittanceAddressStreet] [nvarchar](max) NULL,
	[RemittanceAddressDistrictName] [nvarchar](max) NULL,
	[PostdatedCheckReasonForStop] [nvarchar](max) NULL,
	[ChineseVoucher] [nvarchar](max) NULL,
	[TaxWithholdGroup] [nvarchar](max) NULL,
	[ChineseVoucherType] [nvarchar](max) NULL,
	[CentralBankImportDate] [datetime2](0) NULL,
	[RemittanceAddressCity] [nvarchar](max) NULL,
	[TaxItemGroup] [nvarchar](max) NULL,
	[DefaultDimensionsForOffsetAccountDisplayValue] [nvarchar](max) NULL,
	[PaymentReference] [nvarchar](max) NULL,
	[NACHAIATReceivingDFIQualifier] [nvarchar](max) NULL,
	[ExchangeRate] [float] NULL,
	[RemittanceAddressState] [nvarchar](max) NULL,
	[CheckNumber] [nvarchar](max) NULL,
	[PostdatedCheckNumber] [nvarchar](max) NULL,
	[CreditAmount] [float] NULL,
	[RemittanceAddressZipCode] [nvarchar](max) NULL,
	[MarkedInvoice] [nvarchar](max) NULL,
	[ContactPerson] [nvarchar](max) NULL,
	[FeeAccount] [nvarchar](max) NULL,
	[NACHAIATForeignExchangeReferenceIndicator] [nvarchar](max) NULL,
	[RemittanceAddressCounty] [nvarchar](max) NULL,
	[PostdatedCheckReplacementComments] [nvarchar](max) NULL,
	[PostdatedCheckBankBranch] [nvarchar](max) NULL,
	[ThirdPartyBankAccountId] [nvarchar](max) NULL,
	[Voucher] [nvarchar](max) NULL,
	[CategoryPurpose] [bigint] NULL,
	[ItemWithholdingTaxGroupCode] [nvarchar](max) NULL,
	[OffsetAccountType] [nvarchar](max) NULL,
	[RestrictedForwarding] [nvarchar](max) NULL,
	[MarkedInvoiceCompany] [nvarchar](max) NULL,
	[RemittanceAddressCountryISOCode] [nvarchar](max) NULL,
	[RemittanceLocationId] [nvarchar](max) NULL,
	[PostdatedCheckIsReplacementCheck] [nvarchar](max) NULL,
	[ServiceLevel] [bigint] NULL,
	[CurrencyCode] [nvarchar](max) NULL,
	[OffsetCompany] [nvarchar](max) NULL,
	[PostdatedCheckBankName] [nvarchar](max) NULL,
	[SecondaryExchangeRate] [float] NULL,
	[CentralBankPurposeText] [nvarchar](max) NULL,
	[TaxGroup] [nvarchar](max) NULL,
	[OverrideSalesTax] [nvarchar](max) NULL,
	[PaymentMethodName] [nvarchar](max) NULL,
	[BankTransactionType] [nvarchar](max) NULL,
	[RemittanceAddressTimeZone] [nvarchar](max) NULL,
	[RemittanceAddressDescription] [nvarchar](max) NULL,
	[LocalInstrument] [bigint] NULL,
	[Company] [nvarchar](max) NULL,
	[RemittanceAddressValidFrom] [datetime2](0) NULL,
	[PostdatedCheckOriginalCheckNumber] [nvarchar](max) NULL,
	[NACHAIATForeignExchangeIndicator] [nvarchar](max) NULL,
	[NewJournalBatchNumber] [nvarchar](max) NULL,
	[RemittanceAddressValidTo] [datetime2](0) NULL,
	[NACHAIATOFACScreeningIndicator] [nvarchar](max) NULL,
	[ErrorCodePayment] [nvarchar](max) NULL,
	[OffsetAccountDisplayValue] [nvarchar](max) NULL,
	[PostdatedCheckStopPayment] [nvarchar](max) NULL,
	[NACHAIATForeignExchangeReference] [nvarchar](max) NULL,
	[IsPrepayment] [nvarchar](max) NULL,
	[RemittanceAddressLatitude] [float] NULL,
	[FullPrimaryRemittanceAddress] [nvarchar](max) NULL,
	[CentralBankPurposeCode] [nvarchar](max) NULL,
	[ChargeBearer] [bigint] NULL,
	[DebitAmount] [float] NULL,
	[RemittanceAddressCountry] [nvarchar](max) NULL,
	[NACHAIATOriginatingDFIQualifier] [nvarchar](max) NULL,
	[CalculateWithholdingTax] [nvarchar](max) NULL,
	[PostdatedCheckSalespersonDisplayValue] [nvarchar](max) NULL,
	[FinTagDisplayValue] [nvarchar](max) NULL,
	[OffsetTransactionText] [nvarchar](max) NULL,
	[PostdatedCheckMaturityDate] [datetime2](0) NULL,
	[InstructionKey4] [nvarchar](max) NULL,
	[InstructionKey1] [nvarchar](max) NULL,
	[InstructionKey2] [nvarchar](max) NULL,
	[InstructionKey3] [nvarchar](max) NULL,
	[PaymentSpecification] [nvarchar](max) NULL,
	[PostdatedCheckReceivedDate] [datetime2](0) NULL,
	[DefaultDimensionsForAccountDisplayValue] [nvarchar](max) NULL,
	[RemittanceAddressLongitude] [float] NULL,
	[SettleVoucher] [nvarchar](max) NULL,
	[LastUpdate] [datetime] NULL
) ON [PRIMARY] TEXTIMAGE_ON [PRIMARY]
GO
/****** Object:  View [dbo].[vw_PostDatedChecks_Details]    Script Date: 30/07/2025 12:27:44 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE VIEW [dbo].[vw_PostDatedChecks_Details]
AS
SELECT        dbo.PostdatedChecks.JournalBatchNumber, dbo.VendorPaymentJournalLines.VendorName, dbo.VendorPaymentJournalLines.TransactionText, dbo.PostdatedChecks.PostDatedCheckStatus, dbo.PostdatedChecks.DebitAmount, 
                         dbo.PostdatedChecks.CheckNumber, dbo.PostdatedChecks.LastUpdate, dbo.VendorPaymentJournalLines.PaymentMethodName, dbo.VendorPaymentJournalLines.BankTransactionType, 
                         dbo.PostdatedChecks.AccountDisplayValue, dbo.VendorsV2.VendorGroupId, dbo.VendorPaymentJournalLines.TransactionDate, dbo.VendorPaymentJournalLines.PostdatedCheckMaturityDate
FROM            dbo.PostdatedChecks LEFT OUTER JOIN
                         dbo.VendorsV2 ON dbo.PostdatedChecks.AccountDisplayValue = dbo.VendorsV2.VendorAccountNumber LEFT OUTER JOIN
                         dbo.VendorPaymentJournalLines ON dbo.PostdatedChecks.LineNumber = dbo.VendorPaymentJournalLines.LineNumber AND dbo.PostdatedChecks.JournalBatchNumber = dbo.VendorPaymentJournalLines.JournalBatchNumber
GO
/****** Object:  Table [dbo].[TransferOrderLines]    Script Date: 30/07/2025 12:27:44 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[TransferOrderLines](
	[TransferOrderNumber] [nvarchar](max) NULL,
	[LineNumber] [float] NULL,
	[TransferQuantity] [float] NULL,
	[LineStatus] [nvarchar](max) NULL,
	[ShippingSiteId] [nvarchar](max) NULL,
	[ItemNumber] [nvarchar](max) NULL,
	[ShippingWarehouseId] [nvarchar](max) NULL,
	[RequestedReceiptDate] [datetime2](0) NULL,
	[ShippedQuantity] [float] NULL,
	[ReceivedQuantity] [float] NULL,
	[ReceivingInventoryLotId] [nvarchar](max) NULL,
	[ShippingInventoryLotId] [nvarchar](max) NULL,
	[RemainingShippedQuantity] [float] NULL,
	[RequestedShippingDate] [datetime2](0) NULL,
	[ReceivingTransitInventoryLotId] [nvarchar](max) NULL,
	[ItemBatchNumber] [nvarchar](max) NULL
) ON [PRIMARY] TEXTIMAGE_ON [PRIMARY]
GO
/****** Object:  View [dbo].[vw_TransferOrderLines_Pending_WH]    Script Date: 30/07/2025 12:27:44 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE VIEW [dbo].[vw_TransferOrderLines_Pending_WH]
AS
SELECT        dbo.TransferOrderLines.TransferOrderNumber, dbo.TransferOrderLines.LineNumber, dbo.TransferOrderLines.TransferQuantity, dbo.TransferOrderLines.LineStatus, dbo.TransferOrderLines.ShippingSiteId, 
                         dbo.TransferOrderLines.ItemNumber, dbo.TransferOrderLines.ShippingWarehouseId, dbo.TransferOrderLines.RequestedReceiptDate, dbo.TransferOrderLines.ShippedQuantity, dbo.TransferOrderLines.ReceivedQuantity, 
                         dbo.TransferOrderLines.ReceivingInventoryLotId, dbo.TransferOrderLines.ShippingInventoryLotId, dbo.TransferOrderLines.RemainingShippedQuantity, dbo.TransferOrderLines.RequestedShippingDate, 
                         dbo.TransferOrderLines.ReceivingTransitInventoryLotId, dbo.TransferOrderLines.ItemBatchNumber, dbo.TransferOrderHeaders.TransferOrderStatus, dbo.TransferOrderHeaders.ShippingWarehouseId AS Expr1, 
                         dbo.Mx_Product_Master_new.ProductName, dbo.Mx_Product_Master_new.ProductGroupId, 
                         CASE WHEN dbo.TransferOrderHeaders.[ShippingWarehouseId] = 'WH0001' THEN 1 WHEN dbo.TransferOrderHeaders.[ShippingWarehouseId] = 'WH0002' THEN 8 END AS WH
FROM            dbo.TransferOrderLines INNER JOIN
                         dbo.TransferOrderHeaders ON dbo.TransferOrderLines.TransferOrderNumber = dbo.TransferOrderHeaders.TransferOrderNumber INNER JOIN
                         dbo.Mx_Product_Master_new ON dbo.TransferOrderLines.ItemNumber = dbo.Mx_Product_Master_new.ItemNumber
WHERE        (dbo.TransferOrderHeaders.TransferOrderStatus = N'Created') AND (dbo.TransferOrderHeaders.ShippingWarehouseId IN (N'WH0001', N'WH0002'))
GO
/****** Object:  View [dbo].[vw_TransferOrderLines_Pending_WH_x_upload]    Script Date: 30/07/2025 12:27:44 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO

create view [dbo].[vw_TransferOrderLines_Pending_WH_x_upload]
as
SELECT [TransferOrderNumber]
      ,[LineNumber]
      ,[TransferQuantity]
      ,[LineStatus]
      ,[ShippingSiteId]
      ,[ItemNumber]
      ,[ShippingWarehouseId]
      ,[RequestedReceiptDate]
      ,[ShippedQuantity]
      ,[ReceivedQuantity]
      ,[ReceivingInventoryLotId]
      ,[ShippingInventoryLotId]
      ,[RemainingShippedQuantity]
      ,[RequestedShippingDate]
      ,[ReceivingTransitInventoryLotId]
      ,[ItemBatchNumber]
      ,[TransferOrderStatus]
      ,[Expr1]
      ,[ProductName]
      ,[ProductGroupId]
      ,[WH]
  FROM [MarinaDynamics365].[dbo].[vw_TransferOrderLines_Pending_WH]
  union
  SELECT  [Number]
      , ROW_NUMBER() OVER (PARTITION BY [Number] ORDER BY [Item number]) AS LineNumber
      ,[Quantity]
      ,[TransferOrderStatus]
      ,[ShippingWarehouseId]
      ,[Item number]
	  ,[ShippingWarehouseId]
      ,[RequestedReceiptDate]
	   ,0
	   ,0
	   ,''
	   ,''
	    ,[Quantity]
		,[RequestedReceiptDate]
		,''
		,''
		  ,[TransferOrderStatus]
		    ,[ShippingWarehouseId]
      ,[ProductName]
      ,[ProductGroupId]
      ,[WH]
  FROM [MarinaDynamics365].[dbo].[vw_TransferOrderLines_Pending_WH_Upload]
  where number  not in (SELECT [TransferOrderNumber]   FROM [MarinaDynamics365].[dbo].[vw_TransferOrderLines_Pending_WH])
GO
/****** Object:  Table [dbo].[ItemStockTotal_UploadRaw]    Script Date: 30/07/2025 12:27:44 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[ItemStockTotal_UploadRaw](
	[Item number] [varchar](50) NULL,
	[Product name] [varchar](254) NULL,
	[Search name] [varchar](254) NULL,
	[Consignment item] [varchar](50) NULL,
	[Site] [varchar](50) NULL,
	[Warehouse name] [varchar](50) NULL,
	[Physical inventory] [varchar](50) NULL,
	[Physical reserved] [varchar](50) NULL,
	[Available physical] [varchar](50) NULL,
	[Available physical on exact dimensions] [varchar](50) NULL,
	[Ordered in total] [varchar](150) NULL,
	[On order] [varchar](150) NULL,
	[Ordered reserved] [varchar](150) NULL,
	[Available for reservation] [varchar](150) NULL,
	[Total available] [varchar](150) NULL,
	[Uses warehouse management processes] [varchar](150) NULL,
	[Product identification] [varchar](150) NULL,
	[LastUpdate] [datetime] NULL
) ON [PRIMARY]
GO
/****** Object:  View [dbo].[vw_Mx_Stocks_by_Location]    Script Date: 30/07/2025 12:27:44 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO







CREATE VIEW [dbo].[vw_Mx_Stocks_by_Location]
AS
SELECT        dbo.Mx_Product_Master.[Item number], dbo.Mx_Product_Master.[Product name], dbo.Mx_Product_Master.DrugName, dbo.Mx_Product_Master.Drug_ID, dbo.ItemStockTotal_UploadRaw.Site, dbo.Mx_StoreCode.STORENAME, 
                         dbo.Mx_StoreCode.ShortName, CAST(dbo.ItemStockTotal_UploadRaw.[Available physical] AS DECIMAL(8,2)) [Available physical], dbo.Mx_StoreCode.LocationID ,dbo.ItemStockTotal_UploadRaw.LastUpdate
,dbo.ItemStockTotal_UploadRaw.[Site] +'-'+ dbo.Mx_StoreCode.ShortName [Site2] 
,(SELECT UNITCOST FROM MarinaDynamics365.dbo.Drug_Master dm
where dbo.Mx_Product_Master.Drug_ID=dm.Drug_ID ) UNITCOST
FROM            dbo.Mx_Product_Master INNER JOIN
                         dbo.ItemStockTotal_UploadRaw ON dbo.Mx_Product_Master.[Item number] = dbo.ItemStockTotal_UploadRaw.[Item number] INNER JOIN
                         dbo.Mx_StoreCode ON dbo.ItemStockTotal_UploadRaw.Site = dbo.Mx_StoreCode.STORECODE
GO
/****** Object:  Table [dbo].[Stock_Batch_correction_final_v2]    Script Date: 30/07/2025 12:27:44 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[Stock_Batch_correction_final_v2](
	[Store Code] [varchar](50) NULL,
	[Item number] [varchar](50) NULL,
	[Item Name] [varchar](254) NULL,
	[Site] [varchar](50) NULL,
	[Warehouse] [varchar](50) NULL,
	[Location] [varchar](50) NULL,
	[Old Batch number] [varchar](8000) NULL,
	[New_Batch] [varchar](50) NULL,
	[New_Qty] [varchar](50) NULL,
	[Expiry Date] [varchar](50) NULL,
	[Unit] [varchar](50) NULL,
	[Sales qty] [decimal](38, 2) NULL,
	[Old Available qty] [decimal](18, 2) NULL,
	[New Available qty] [decimal](8, 2) NULL,
	[found batch] [int] NULL,
	[all Batch On Hand] [varchar](1) NOT NULL,
	[Remarks] [varchar](32) NULL
) ON [PRIMARY]
GO
/****** Object:  View [dbo].[vw_Stock_Batch_correction_final_w_batch_lacking]    Script Date: 30/07/2025 12:27:44 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO




create view [dbo].[vw_Stock_Batch_correction_final_w_batch_lacking]

as
SELECT [Store Code]
      ,[Item number]
      ,[Item Name]
	 , [Store Code] +  [Item number]  ref
      ,[Site]
      ,[Warehouse]
      ,[Location]
	  ,[Old Batch number]
	  ,[Sales qty]
      ,[New_Batch]
	   ,CASE WHEN [Sales qty]<= isnull([New_Qty],0) THEN [Sales qty] ELSE isnull([New_Qty],0)  END [New_Qty]
	  ,[Sales qty] - CASE WHEN [Sales qty]<= isnull([New_Qty],0) THEN [Sales qty] ELSE isnull([New_Qty],0)  END  dIFF
      ,[Expiry Date]
      ,[Unit]
	 , [all Batch On Hand]
      ,REMARKS
      FROM [MarinaDynamics365].[dbo].[Stock_Batch_correction_final_v2]
	 where isnull([New_Batch],'x')='x' and remarks = 'with batch but not enough Stocks'
GO
/****** Object:  View [dbo].[vw_Stock_Batch_correction_final_no_batch_no_stocks]    Script Date: 30/07/2025 12:27:44 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO


create view [dbo].[vw_Stock_Batch_correction_final_no_batch_no_stocks]
as
SELECT [Store Code]
      ,[Item number]
      ,[Item Name]
	   , [Store Code] +  [Item number]  ref
      ,[Site]
      ,[Warehouse]
      ,[Location]
	  ,[Old Batch number]
	  ,[Sales qty]
      ,[New_Batch]
	   ,CASE WHEN [Sales qty]<= isnull([New_Qty],0) THEN [Sales qty] ELSE isnull([New_Qty],0)  END [New_Qty]
	  ,[Sales qty] - CASE WHEN [Sales qty]<= isnull([New_Qty],0) THEN [Sales qty] ELSE isnull([New_Qty],0)  END  dIFF
      ,[Expiry Date]
      ,[Unit]
	 , [all Batch On Hand]
      ,REMARKS
      FROM [MarinaDynamics365].[dbo].[Stock_Batch_correction_final_v2]
	 where isnull([New_Batch],'x')='x' and remarks='No batch and no stocks'
GO
/****** Object:  View [dbo].[vw_Stock_Batch_correction_final_w_batch_more_stocks]    Script Date: 30/07/2025 12:27:44 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO




create view [dbo].[vw_Stock_Batch_correction_final_w_batch_more_stocks]

as
SELECT [Store Code]
      ,[Item number]
      ,[Item Name]
	 , [Store Code] +  [Item number]  ref
      ,[Site]
      ,[Warehouse]
      ,[Location]
	  ,[Old Batch number]
	  ,[Sales qty]
      ,[New_Batch]
	   ,CASE WHEN [Sales qty]<= isnull([New_Qty],0) THEN [Sales qty] ELSE isnull([New_Qty],0)  END [New_Qty]
	  ,[Sales qty] - CASE WHEN [Sales qty]<= isnull([New_Qty],0) THEN [Sales qty] ELSE isnull([New_Qty],0)  END  dIFF
      ,[Expiry Date]
      ,[Unit]
	 , [all Batch On Hand]
      ,REMARKS
      FROM [MarinaDynamics365].[dbo].[Stock_Batch_correction_final_v2]
	 where isnull([New_Batch],'x')='x' and remarks = 'other batch with enough Stocks'
GO
/****** Object:  View [dbo].[vw_Mx_Product_Master_new_w_location]    Script Date: 30/07/2025 12:27:44 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO



create view [dbo].[vw_Mx_Product_Master_new_w_location]
as
SELECT  [ItemNumber]
      ,[ProductName]
      ,[ProductGroupId]
      ,[RetailProductCategoryname]
      ,[SalesSalesTaxItemGroupCode]
      ,[Drug_id]
      ,s.STORECODE
	  ,s.LocationID
	  ,s.ShortName
	  ,Order_Group
	

  FROM [MarinaDynamics365].[dbo].[Mx_Product_Master_new] p,
  MarinaDynamics365.dbo.Mx_StoreCode s
  where s.ShortName<>'DXB0024'

GO
/****** Object:  View [dbo].[vw_TransferOrder_to_WH0001]    Script Date: 30/07/2025 12:27:44 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO

create view [dbo].[vw_TransferOrder_to_WH0001]
as

SELECT        dbo.TransferOrderHeaders.TransferOrderNumber, dbo.TransferOrderHeaders.RequestedReceiptDate, dbo.TransferOrderHeaders.ShippingWarehouseId, dbo.TransferOrderHeaders.ReceivingWarehouseId, 
                         dbo.TransferOrderHeaders.TransferOrderStatus, dbo.TransferOrderLines.TransferOrderNumber AS Expr1, dbo.TransferOrderLines.ItemNumber, dbo.TransferOrderLines.TransferQuantity, 
                         dbo.TransferOrderLines.ItemBatchNumber, dbo.Mx_Product_Master.[Product name], dbo.TransferOrderHeaders.ShippingAddressName
FROM            dbo.TransferOrderHeaders INNER JOIN
                         dbo.TransferOrderLines ON dbo.TransferOrderHeaders.TransferOrderNumber = dbo.TransferOrderLines.TransferOrderNumber INNER JOIN
                         dbo.Mx_Product_Master ON dbo.TransferOrderLines.ItemNumber = dbo.Mx_Product_Master.[Item number]

						 and   dbo.TransferOrderHeaders.TransferOrderNumber in  (select [TransferOrderNumber] FROM [MarinaDynamics365].[dbo].[TransferOrderHeaders]
  where 
      [ReceivingWarehouseId]='WH0001'
	--  and [TransferOrderStatus]='Received'
	 -- and [RequestedReceiptDate]>'2024-01-31'
	 and [ShippingWarehouseId] not like 'WH%')
GO
/****** Object:  Table [dbo].[PriceMaster_UploadRaw]    Script Date: 30/07/2025 12:27:44 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[PriceMaster_UploadRaw](
	[Relation] [varchar](50) NULL,
	[Currency] [varchar](50) NULL,
	[Party code type] [varchar](50) NULL,
	[Account selection] [varchar](50) NULL,
	[Product code type] [varchar](50) NULL,
	[Item] [varchar](50) NULL,
	[Configuration] [varchar](50) NULL,
	[Unit] [varchar](50) NULL,
	[From date] [varchar](50) NULL,
	[To date] [varchar](50) NULL,
	[From] [varchar](50) NULL,
	[To] [varchar](50) NULL,
	[Amount in transaction currency] [varchar](50) NULL,
	[Price unit] [varchar](50) NULL,
	[Discount percentage 1] [varchar](50) NULL,
	[Attribute-based pricing ID] [varchar](50) NULL,
	[Fixed amount] [varchar](50) NULL,
	[Find next] [varchar](50) NULL
) ON [PRIMARY]
GO
/****** Object:  View [dbo].[vw_Mx_Item_Price_Retail]    Script Date: 30/07/2025 12:27:44 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO


CREATE VIEW [dbo].[vw_Mx_Item_Price_Retail]
AS
SELECT        dbo.Mx_Product_Master.[Item number], dbo.Mx_Product_Master.[Product name], dbo.Mx_Product_Master.DrugName, dbo.Mx_Product_Master.Drug_ID, dbo.PriceMaster_UploadRaw.[Amount in transaction currency] 
FROM            dbo.Mx_Product_Master INNER JOIN
                         dbo.PriceMaster_UploadRaw ON dbo.Mx_Product_Master.[Item number] = dbo.PriceMaster_UploadRaw.Item
WHERE        (dbo.PriceMaster_UploadRaw.[Account selection] = 'UAE-RETAIL')
GO
/****** Object:  Table [dbo].[MX_Product_Cost_SPrice]    Script Date: 30/07/2025 12:27:44 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[MX_Product_Cost_SPrice](
	[Item number] [varchar](50) NULL,
	[Product name] [varchar](254) NULL,
	[Price] [varchar](50) NULL,
	[Item sales tax group] [varchar](50) NULL,
	[Price2] [varchar](50) NULL,
	[Vendor] [varchar](50) NULL
) ON [PRIMARY]
GO
/****** Object:  View [dbo].[vw_Product_w_Price_Tax]    Script Date: 30/07/2025 12:27:44 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO



/****** Script for SelectTopNRows command from SSMS  ******/
create view [dbo].[vw_Product_w_Price_Tax]
as
SELECT [ItemNumber]
      ,[ProductName]
	   ,[Drug_id]
 
      ,[SalesSalesTaxItemGroupCode]
      ,[SalesUnitSymbol]
 ,(    SELECT top 1 [Price2]
  FROM [MarinaDynamics365].[dbo].[MX_Product_Cost_SPrice] c
  where c.[Item number]=m.ItemNumber ) Cost
      ,(SELECT  top 1
   [Amount in transaction currency]
  FROM [MarinaDynamics365].[dbo].[vw_Mx_Item_Price_Retail] r
  where r.[Item number]=m.ItemNumber) [Selling_Price]

  FROM [MarinaDynamics365].[dbo].[Mx_Product_Master_new] m
GO
/****** Object:  View [dbo].[vw_Drug_Batch_Stock_ordered_SUM_from_bi]    Script Date: 30/07/2025 12:27:44 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO




create view [dbo].[vw_Drug_Batch_Stock_ordered_SUM_from_bi]
as
SELECT [Product Id] ItemNumber
,(Select Drug_id  FROM [MarinaDynamics365].[dbo].[Mx_Product_Master_new] dm
where dm.ItemNumber=i.[Product Id]) Drug_id
   
      ,sum([Available Qty]) Stock
	   ,sum([Ordered]) Ordered
 
      ,[Location Id] SiteID
	  ,(select Locationid from [MarinaDynamics365].dbo.Mx_StoreCode s
	  where s.STORECODE=i.[Location Id]) Locationid
   
  FROM [192.168.70.86].[crm_reports].[dbo].[fInventory] i
  where [Type Of Location]='Storage'

  group by [Product Id]
  ,[Location Id] 

GO
/****** Object:  View [dbo].[vw_TransferOrderLines_Pending_ALL]    Script Date: 30/07/2025 12:27:44 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE VIEW [dbo].[vw_TransferOrderLines_Pending_ALL]
AS
SELECT        dbo.TransferOrderLines.TransferOrderNumber, dbo.TransferOrderLines.LineNumber, dbo.TransferOrderLines.TransferQuantity, dbo.TransferOrderLines.LineStatus, dbo.TransferOrderLines.ShippingSiteId, 
                         dbo.TransferOrderLines.ItemNumber, dbo.TransferOrderLines.ShippingWarehouseId, dbo.TransferOrderLines.RequestedReceiptDate, dbo.TransferOrderLines.ShippedQuantity, dbo.TransferOrderLines.ReceivedQuantity, 
                         dbo.TransferOrderLines.ReceivingInventoryLotId, dbo.TransferOrderLines.ShippingInventoryLotId, dbo.TransferOrderLines.RemainingShippedQuantity, dbo.TransferOrderLines.RequestedShippingDate, 
                         dbo.TransferOrderLines.ReceivingTransitInventoryLotId, dbo.TransferOrderLines.ItemBatchNumber, dbo.TransferOrderHeaders.TransferOrderStatus
FROM            dbo.TransferOrderLines INNER JOIN
                         dbo.TransferOrderHeaders ON dbo.TransferOrderLines.TransferOrderNumber = dbo.TransferOrderHeaders.TransferOrderNumber
WHERE        (dbo.TransferOrderHeaders.TransferOrderStatus IN ('Created', 'Shipped'))
GO
/****** Object:  View [dbo].[vw_TransferOrderHeaders_Pending]    Script Date: 30/07/2025 12:27:44 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE VIEW [dbo].[vw_TransferOrderHeaders_Pending]
AS
SELECT        TransferOrderNumber, RequestedReceiptDate, ShippingWarehouseId, ReceivingWarehouseId, ShippingAddressName, TransferOrderStatus, ReceivingAddressName, RequestedShippingDate
FROM            dbo.TransferOrderHeaders
WHERE        (TransferOrderStatus = N'Created')
GO
/****** Object:  Table [dbo].[ReleasedProductCreationsV2_auto]    Script Date: 30/07/2025 12:27:44 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[ReleasedProductCreationsV2_auto](
	[ItemNumber] [int] NULL,
	[ProductGroupId] [varchar](255) NULL,
	[ProductType] [varchar](255) NULL,
	[InventoryUnitSymbol] [varchar](255) NULL,
	[RetailProductCategoryname] [varchar](255) NULL,
	[ProductNumber] [int] NULL,
	[BOMUnitSymbol] [varchar](255) NULL,
	[SalesSalesTaxItemGroupCode] [varchar](255) NULL,
	[PurchaseSalesTaxItemGroupCode] [varchar](255) NULL,
	[ProductName] [varchar](255) NULL,
	[ImportDate] [datetime] NULL
) ON [PRIMARY]
GO
/****** Object:  Table [dbo].[Mx_Product_Master_Inactive]    Script Date: 30/07/2025 12:27:44 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[Mx_Product_Master_Inactive](
	[ItemNumber] [varchar](50) NULL,
	[ProductName] [varchar](254) NULL,
	[Status] [varchar](50) NULL
) ON [PRIMARY]
GO
/****** Object:  View [dbo].[vw_ReleasedProductCreationsV2_auto]    Script Date: 30/07/2025 12:27:44 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE VIEW [dbo].[vw_ReleasedProductCreationsV2_auto]
AS
SELECT        dbo.ReleasedProductCreationsV2_auto.ItemNumber, dbo.ReleasedProductCreationsV2_auto.ProductName, '' AS PurchaseUnitSymbol, dbo.ReleasedProductCreationsV2_auto.ProductGroupId, 
                         dbo.ReleasedProductCreationsV2_auto.RetailProductCategoryname, dbo.ReleasedProductCreationsV2_auto.BOMUnitSymbol, '' AS SearchName, dbo.ReleasedProductCreationsV2_auto.SalesSalesTaxItemGroupCode, 
                         '' AS ProductDescription, dbo.ReleasedProductCreationsV2_auto.PurchaseSalesTaxItemGroupCode, dbo.items_d365.[Old Drug ID] AS Drug_id, dbo.VendorProductDescriptionsV2.VendorProductNumber AS Comments, 
                         ISNULL(dbo.vw_ProductSpecificUnitOfMeasureConversions_pcs.Factor, 1) AS Factor, '' AS SalesUnitSymbol
FROM            dbo.ReleasedProductCreationsV2_auto LEFT OUTER JOIN
                         dbo.vw_ProductSpecificUnitOfMeasureConversions_pcs ON dbo.ReleasedProductCreationsV2_auto.ItemNumber = dbo.vw_ProductSpecificUnitOfMeasureConversions_pcs.ProductNumber LEFT OUTER JOIN
                         dbo.VendorProductDescriptionsV2 ON dbo.ReleasedProductCreationsV2_auto.ItemNumber = dbo.VendorProductDescriptionsV2.ItemNumber LEFT OUTER JOIN
                         dbo.items_d365 ON dbo.ReleasedProductCreationsV2_auto.ItemNumber = dbo.items_d365.[Item number]
WHERE        (dbo.ReleasedProductCreationsV2_auto.ProductGroupId <> N'Service') AND (dbo.ReleasedProductCreationsV2_auto.ItemNumber NOT IN
                             (SELECT        ItemNumber
                               FROM            dbo.Mx_Product_Master_Inactive))
GO
/****** Object:  Table [dbo].[PurchaseOrderConfirmationLines]    Script Date: 30/07/2025 12:27:44 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[PurchaseOrderConfirmationLines](
	[dataAreaId] [nvarchar](max) NULL,
	[PurchaseOrderNumber] [nvarchar](max) NULL,
	[LineNumber] [bigint] NULL,
	[ConfirmationNumber] [nvarchar](max) NULL,
	[ConfirmationDate] [datetime2](0) NULL,
	[ProcurementProductCategoryName] [nvarchar](max) NULL,
	[FixedAssetNumber] [nvarchar](max) NULL,
	[ProjectSalesUnitSymbol] [nvarchar](max) NULL,
	[OrderedPurchaseQuantity] [float] NULL,
	[OrderVendorAccountNumber] [nvarchar](max) NULL,
	[DeliveryAddressBuildingCompliment] [nvarchar](max) NULL,
	[ProjectCategoryId] [nvarchar](max) NULL,
	[AccountingDistributionTemplateName] [nvarchar](max) NULL,
	[ItemNumber] [nvarchar](max) NULL,
	[DeliveryAddressDescription] [nvarchar](max) NULL,
	[MultilineDiscountPercentage] [float] NULL,
	[DeliveryCityInKana] [nvarchar](max) NULL,
	[LineDiscountAmount] [float] NULL,
	[ProductStyleId] [nvarchar](max) NULL,
	[ProjectTaxGroupCode] [nvarchar](max) NULL,
	[ProjectTaxItemGroupCode] [nvarchar](max) NULL,
	[Barcode] [nvarchar](max) NULL,
	[IsNewFixedAsset] [nvarchar](max) NULL,
	[ProductConfigurationId] [nvarchar](max) NULL,
	[IsIntrastatTriangularDeal] [nvarchar](max) NULL,
	[Tax1099StateId] [nvarchar](max) NULL,
	[IsPartialDeliveryPrevented] [nvarchar](max) NULL,
	[MultilineDiscountAmount] [float] NULL,
	[Tax1099Type] [nvarchar](max) NULL,
	[RequestedDeliveryDate] [datetime2](0) NULL,
	[ItemBatchNumber] [nvarchar](max) NULL,
	[DeliveryAddressCountryRegionId] [nvarchar](max) NULL,
	[DeliveryAddressLatitude] [float] NULL,
	[ReceivingWarehouseId] [nvarchar](max) NULL,
	[DeliveryAddressCity] [nvarchar](max) NULL,
	[ConfirmedDeliveryDate] [datetime2](0) NULL,
	[PurchaseUnitSymbol] [nvarchar](max) NULL,
	[RequesterPersonnelNumber] [nvarchar](max) NULL,
	[ProjectId] [nvarchar](max) NULL,
	[ProjectLinePropertyId] [nvarchar](max) NULL,
	[DeliveryAddressDistrictName] [nvarchar](max) NULL,
	[DeliveryAddressCountyId] [nvarchar](max) NULL,
	[ProductSizeId] [nvarchar](max) NULL,
	[FixedPriceCharges] [float] NULL,
	[DeliveryAddressZipCode] [nvarchar](max) NULL,
	[DeliveryAddressDunsNumber] [nvarchar](max) NULL,
	[PurchasePriceQuantity] [float] NULL,
	[DeliveryAddressName] [nvarchar](max) NULL,
	[Tax1099BoxId] [nvarchar](max) NULL,
	[BOMId] [nvarchar](max) NULL,
	[FixedAssetTransactionType] [nvarchar](max) NULL,
	[DeliveryAddressStreetNumber] [nvarchar](max) NULL,
	[DeliveryAddressStreetInKana] [nvarchar](max) NULL,
	[RequestedShipDate] [datetime2](0) NULL,
	[IsDeliveryAddressPrivate] [nvarchar](max) NULL,
	[OriginStateId] [nvarchar](max) NULL,
	[ItemWithholdingTaxGroupCode] [nvarchar](max) NULL,
	[MainAccountIdDisplayValue] [nvarchar](max) NULL,
	[OrderedInventoryStatusId] [nvarchar](max) NULL,
	[CatchWeightUnitSymbol] [nvarchar](max) NULL,
	[DeliveryAddressCountryRegionISOCode] [nvarchar](max) NULL,
	[ReceivingSiteId] [nvarchar](max) NULL,
	[ProjectSalesCurrencyCode] [nvarchar](max) NULL,
	[IntrastatTransactionCode] [nvarchar](max) NULL,
	[ArePricesIncludingSalesTax] [nvarchar](max) NULL,
	[DeliveryAddressLocationId] [nvarchar](max) NULL,
	[ProjectActivityNumber] [nvarchar](max) NULL,
	[ConfirmedShipDate] [datetime2](0) NULL,
	[SalesTaxItemGroupCode] [nvarchar](max) NULL,
	[RouteId] [nvarchar](max) NULL,
	[ProductVersionId] [nvarchar](max) NULL,
	[TotalLineSalesTaxAmount] [float] NULL,
	[IntrastatStatisticsProcedureCode] [nvarchar](max) NULL,
	[InvoiceVendorAccountNumber] [nvarchar](max) NULL,
	[LineDescription] [nvarchar](max) NULL,
	[GSTHSTTaxType] [nvarchar](max) NULL,
	[DeliveryAddressStreet] [nvarchar](max) NULL,
	[ConfirmedShippingDate] [datetime2](0) NULL,
	[CustomerReference] [nvarchar](max) NULL,
	[SalesTaxGroupCode] [nvarchar](max) NULL,
	[CustomerRequisitionNumber] [nvarchar](max) NULL,
	[PurchasePrice] [float] NULL,
	[LineDiscountPercentage] [float] NULL,
	[FixedAssetValueModelId] [nvarchar](max) NULL,
	[OrderedCatchWeightQuantity] [float] NULL,
	[AllowedUnderdeliveryPercentage] [float] NULL,
	[AllowedOverdeliveryPercentage] [float] NULL,
	[DeliveryAddressLongitude] [float] NULL,
	[FixedAssetGroupId] [nvarchar](max) NULL,
	[PurchaseOrderLineStatus] [nvarchar](max) NULL,
	[IntrastatCommodityCode] [nvarchar](max) NULL,
	[DefaultLedgerDimensionDisplayValue] [nvarchar](max) NULL,
	[DeliveryAddressTimeZone] [nvarchar](max) NULL,
	[ProductColorId] [nvarchar](max) NULL,
	[DeliveryAddressStateId] [nvarchar](max) NULL,
	[IntrastatTransportModeCode] [nvarchar](max) NULL,
	[Tax1099StateAmount] [float] NULL,
	[DeliveryAddressPostBox] [nvarchar](max) NULL,
	[LineAmount] [float] NULL,
	[OriginCountryRegionId] [nvarchar](max) NULL,
	[IntrastatPortId] [nvarchar](max) NULL,
	[Tax1099Amount] [float] NULL,
	[BarCodeSetupId] [nvarchar](max) NULL,
	[VendorInvoiceMatchingPolicy] [nvarchar](max) NULL,
	[ProjectSalesPrice] [float] NULL,
	[RequestedShippingDate] [datetime2](0) NULL,
	[PurchaseOrderLineCreationMethod] [nvarchar](max) NULL,
	[WithholdingTaxGroupCode] [nvarchar](max) NULL,
	[ExternalItemNumber] [nvarchar](max) NULL,
	[FormattedDeliveryAddress] [nvarchar](max) NULL,
	[IsLineStopped] [nvarchar](max) NULL
) ON [PRIMARY] TEXTIMAGE_ON [PRIMARY]
GO
/****** Object:  View [dbo].[vw_PurchaseOrderConfirmationLines_Ordered_Delivered]    Script Date: 30/07/2025 12:27:44 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE VIEW [dbo].[vw_PurchaseOrderConfirmationLines_Ordered_Delivered]
AS
SELECT        dbo.PurchaseOrderConfirmationLines.PurchaseOrderNumber, dbo.PurchaseOrderConfirmationLines.LineNumber, dbo.PurchaseOrderConfirmationLines.ItemNumber, dbo.PurchaseOrderConfirmationLines.LineDescription, 
                         dbo.PurchaseOrderConfirmationLines.OrderedPurchaseQuantity AS Ordered, SUM(PurchaseOrderConfirmationLines_1.OrderedPurchaseQuantity) AS Delivered
FROM            dbo.PurchaseOrderConfirmationLines INNER JOIN
                         dbo.PurchaseOrderConfirmationLines AS PurchaseOrderConfirmationLines_1 ON dbo.PurchaseOrderConfirmationLines.PurchaseOrderNumber = PurchaseOrderConfirmationLines_1.PurchaseOrderNumber AND 
                         dbo.PurchaseOrderConfirmationLines.LineNumber = PurchaseOrderConfirmationLines_1.LineNumber AND dbo.PurchaseOrderConfirmationLines.ItemNumber = PurchaseOrderConfirmationLines_1.ItemNumber AND 
                         dbo.PurchaseOrderConfirmationLines.ConfirmationDate <> PurchaseOrderConfirmationLines_1.ConfirmationDate
WHERE        (dbo.PurchaseOrderConfirmationLines.ConfirmationDate =
                             (SELECT        TOP (1) ConfirmationDate
                               FROM            dbo.PurchaseOrderConfirmationLines AS c2
                               WHERE        (PurchaseOrderNumber = dbo.PurchaseOrderConfirmationLines.PurchaseOrderNumber)
                               ORDER BY ConfirmationDate))
GROUP BY dbo.PurchaseOrderConfirmationLines.PurchaseOrderNumber, dbo.PurchaseOrderConfirmationLines.LineNumber, dbo.PurchaseOrderConfirmationLines.ItemNumber, dbo.PurchaseOrderConfirmationLines.LineDescription, 
                         dbo.PurchaseOrderConfirmationLines.OrderedPurchaseQuantity
GO
/****** Object:  Table [dbo].[SalesAgreement_LatestPrice]    Script Date: 30/07/2025 12:27:44 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[SalesAgreement_LatestPrice](
	[ItemNumber] [int] NULL,
	[PriceApplicableFromDate] [datetime] NULL,
	[PriceApplicableToDate] [datetime] NULL,
	[PriceCustomerGroupCode] [varchar](255) NULL,
	[Price] [float] NULL,
	[QuantityUnitySymbol] [varchar](255) NULL
) ON [PRIMARY]
GO
/****** Object:  View [dbo].[vw_Mx_PriceMaster]    Script Date: 30/07/2025 12:27:44 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE VIEW [dbo].[vw_Mx_PriceMaster]
AS
SELECT        dbo.SalesAgreement_LatestPrice.ItemNumber AS Item, dbo.Mx_Product_Master_new.Drug_id, dbo.Mx_Product_Master_new.ProductName AS DrugName, dbo.SalesAgreement_LatestPrice.Price AS Selling_Price
FROM            dbo.SalesAgreement_LatestPrice LEFT OUTER JOIN
                         dbo.Mx_Product_Master_new ON dbo.SalesAgreement_LatestPrice.ItemNumber = dbo.Mx_Product_Master_new.ItemNumber
WHERE        (dbo.SalesAgreement_LatestPrice.PriceCustomerGroupCode = 'UAE-RETAIL') AND (NOT (dbo.SalesAgreement_LatestPrice.ItemNumber IN ('102880', '102604', '103658', '102605', '108379', '110488', '111555', '108378')))
GO
/****** Object:  View [dbo].[vw_TransferOrder_Pending_Sum]    Script Date: 30/07/2025 12:27:44 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE VIEW [dbo].[vw_TransferOrder_Pending_Sum]
AS
SELECT        dbo.TransferOrderHeaders.ReceivingWarehouseId, dbo.TransferOrderLines.ItemNumber, SUM(dbo.TransferOrderLines.TransferQuantity) AS Pending_Qty
FROM            dbo.TransferOrderHeaders LEFT OUTER JOIN
                         dbo.TransferOrderLines ON dbo.TransferOrderHeaders.TransferOrderNumber = dbo.TransferOrderLines.TransferOrderNumber
WHERE        (dbo.TransferOrderHeaders.ShippingWarehouseId IN (N'WH0001', N'WH0002')) AND (dbo.TransferOrderHeaders.TransferOrderStatus IN (N'Shipped', N'Created'))
GROUP BY dbo.TransferOrderHeaders.ReceivingWarehouseId, dbo.TransferOrderLines.ItemNumber
GO
/****** Object:  View [dbo].[vw_TransferOrder_Pending_Sum_Shipped]    Script Date: 30/07/2025 12:27:44 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO


CREATE VIEW [dbo].[vw_TransferOrder_Pending_Sum_Shipped]
AS
SELECT        dbo.TransferOrderHeaders.ReceivingWarehouseId, dbo.TransferOrderLines.ItemNumber, SUM(dbo.TransferOrderLines.TransferQuantity) AS Pending_Qty
FROM            dbo.TransferOrderHeaders LEFT OUTER JOIN
                         dbo.TransferOrderLines ON dbo.TransferOrderHeaders.TransferOrderNumber = dbo.TransferOrderLines.TransferOrderNumber
WHERE        (dbo.TransferOrderHeaders.ShippingWarehouseId IN (N'WH0001', N'WH0002')) AND (dbo.TransferOrderHeaders.TransferOrderStatus IN (N'Shipped'))
GROUP BY dbo.TransferOrderHeaders.ReceivingWarehouseId, dbo.TransferOrderLines.ItemNumber
GO
/****** Object:  Table [dbo].[Negative_Sales_Upload_Raw]    Script Date: 30/07/2025 12:27:44 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[Negative_Sales_Upload_Raw](
	[Statement number] [varchar](50) NULL,
	[Store Code] [varchar](50) NULL,
	[Item number] [varchar](50) NULL,
	[Item Name] [varchar](254) NULL,
	[Site] [varchar](50) NULL,
	[Warehouse] [varchar](50) NULL,
	[Location] [varchar](50) NULL,
	[Batch number] [varchar](50) NULL,
	[Expiry Date] [varchar](50) NULL,
	[Unit] [varchar](50) NULL,
	[Sales qty] [varchar](50) NULL,
	[Available qty] [varchar](50) NULL
) ON [PRIMARY]
GO
/****** Object:  Table [dbo].[CRM_Error_Upload_Raw]    Script Date: 30/07/2025 12:27:44 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[CRM_Error_Upload_Raw](
	[Integration log id] [varchar](50) NULL,
	[Order_id] [varchar](50) NULL,
	[Order_source] [varchar](50) NULL,
	[Branch_name] [varchar](50) NULL,
	[Branch_id] [varchar](50) NULL,
	[Agent_name] [varchar](50) NULL,
	[Status] [varchar](50) NULL,
	[With_insurance] [varchar](50) NULL,
	[Patient_name] [varchar](50) NULL,
	[Driver] [varchar](50) NULL,
	[Schedule_date] [varchar](50) NULL,
	[Payment_method] [varchar](50) NULL,
	[Reference_number] [varchar](50) NULL,
	[Sub_total] [varchar](50) NULL,
	[Delivery_charges] [varchar](50) NULL,
	[Discount] [varchar](50) NULL,
	[CRM total] [varchar](50) NULL,
	[Header status] [varchar](50) NULL,
	[Latest status] [varchar](50) NULL,
	[Header remarks] [varchar](300) NULL,
	[Sales order] [varchar](254) NULL,
	[parnter_name] [varchar](254) NULL,
	[additional_charges] [varchar](50) NULL,
	[Settled] [varchar](50) NULL,
	[Voucher] [varchar](50) NULL,
	[SKU] [varchar](50) NULL,
	[Name] [varchar](254) NULL,
	[Quantity] [varchar](50) NULL,
	[Price_without_vat] [varchar](254) NULL,
	[Vat_value] [varchar](50) NULL,
	[Price_with_vat] [varchar](50) NULL,
	[Line discount] [varchar](50) NULL,
	[Vat] [varchar](50) NULL,
	[Line number] [varchar](50) NULL,
	[Line status] [varchar](50) NULL,
	[Line remarks] [varchar](50) NULL,
	[Batch] [varchar](50) NULL,
	[Expiry] [varchar](50) NULL
) ON [PRIMARY]
GO
/****** Object:  View [dbo].[vw_UNPOSTED_ITEMS]    Script Date: 30/07/2025 12:27:44 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO



create view [dbo].[vw_UNPOSTED_ITEMS]
AS
SELECT 
       [Branch_id]
   
       ,[SKU]
      ,[Name]
	   ,[Batch]
      ,[Quantity]
      ,'CRM' Remarks

  

  FROM [MarinaDynamics365].[dbo].[CRM_Error_Upload_Raw]
  where  SKU<>''
union

  SELECT [Store Code]
      ,[Item number]
      ,[Item Name]
	   ,[Batch number]
      ,[Sales qty]
	 
      
	  ,(SELECT 
        case when [DIVISION]='Online' then '800 Negative Sales'
			 when [DIVISION] in ('Hospital','Retail') then 'Marina Negative Sales'
			 end
       FROM [MarinaDynamics365].[dbo].[Mx_StoreCode] s
	   where s.STORECODE=u. [Store Code]) Remarks
  FROM [MarinaDynamics365].[dbo].[Negative_Sales_Upload_Raw]  u
GO
/****** Object:  View [dbo].[vw_UNPOSTED_ITEMS_Sum]    Script Date: 30/07/2025 12:27:44 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
create view [dbo].[vw_UNPOSTED_ITEMS_Sum]
as

SELECT  [Branch_id]
       ,[SKU]
   
      ,SUM(cast([Quantity] as decimal(8,2))) Qty_Unposted
      
  FROM [MarinaDynamics365].[dbo].[vw_UNPOSTED_ITEMS]
  where [Branch_id]<>'Courier'
  group by 
  [Branch_id]
       ,[SKU]
GO
/****** Object:  Table [dbo].[HSInventSums_final]    Script Date: 30/07/2025 12:27:44 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[HSInventSums_final](
	[ItemId] [int] NULL,
	[InventDim_InventSiteId] [varchar](255) NULL,
	[InventDim_wMSLocationId] [varchar](255) NULL,
	[inventBatchId] [varchar](255) NULL,
	[AvailPhysical] [float] NULL,
	[Ordered] [float] NULL,
	[UpdateTime] [datetime] NULL
) ON [PRIMARY]
GO
/****** Object:  View [dbo].[vw_Drug_Batch_Stock_ordered_SUM_HSInventSums_final]    Script Date: 30/07/2025 12:27:44 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO




create view [dbo].[vw_Drug_Batch_Stock_ordered_SUM_HSInventSums_final]
as

  SELECT [ItemId] ItemNumber
  ,(Select Drug_id  FROM [MarinaDynamics365].[dbo].[Mx_Product_Master_new] dm
where dm.ItemNumber=i.[ItemId] ) Drug_id
  ,sum([AvailPhysical]) Stock
	   ,sum([Ordered]) Ordered
	    ,[InventDim_InventSiteId] SiteID
		 ,(select Locationid from [MarinaDynamics365].dbo.Mx_StoreCode s
	  where s.STORECODE=i.[InventDim_InventSiteId]) Locationid

    
  FROM MarinaDynamics365.[dbo].[HSInventSums_final] i
  where InventDim_wMSLocationId='Storage'

   group by [ItemId]
  ,[InventDim_InventSiteId] 
GO
/****** Object:  View [dbo].[vw_Drug_Batch_Stock_ordered_SUM_97]    Script Date: 30/07/2025 12:27:44 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO





create view [dbo].[vw_Drug_Batch_Stock_ordered_SUM_97]
as

  SELECT [ItemId] ItemNumber
  ,(Select Drug_id  FROM [MarinaDynamics365].[dbo].[Mx_Product_Master_new] dm
where dm.ItemNumber=i.[ItemId] ) Drug_id
  ,sum([AvailPhysical]) Stock
	   ,sum([Ordered]) Ordered
	    ,[InventDim_InventSiteId] SiteID
		 ,(select Locationid from [MarinaDynamics365].dbo.Mx_StoreCode s
	  where s.STORECODE=i.[InventDim_InventSiteId]) Locationid

    
  FROM [192.168.70.97].[marinadashboard].[dbo].[HSInventSums] i
  where InventDim_wMSLocationId='Storage'

   group by [ItemId]
  ,[InventDim_InventSiteId] 
GO
/****** Object:  Table [dbo].[Stock_Batch_correction_final_w_batch_more_Stocks_corrected]    Script Date: 30/07/2025 12:27:44 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[Stock_Batch_correction_final_w_batch_more_Stocks_corrected](
	[Store Code] [varchar](50) NULL,
	[Item number] [varchar](50) NULL,
	[Item Name] [varchar](254) NULL,
	[ref] [varchar](354) NULL,
	[Site] [varchar](50) NULL,
	[Warehouse] [varchar](50) NULL,
	[Location] [varchar](50) NULL,
	[Old Batch number] [varchar](50) NULL,
	[Sales qty] [decimal](38, 2) NULL,
	[New_Batch] [varchar](50) NULL,
	[Batch number] [varchar](50) NULL,
	[Available physical] [varchar](50) NULL,
	[New_Qty] [decimal](38, 2) NULL,
	[dIFF] [decimal](38, 2) NULL,
	[Expiry Date] [varchar](50) NULL,
	[Unit] [varchar](50) NULL,
	[all Batch On Hand] [nvarchar](max) NULL,
	[REMARKS] [varchar](50) NULL
) ON [PRIMARY] TEXTIMAGE_ON [PRIMARY]
GO
/****** Object:  Table [dbo].[Stock_Batch_correction_final_w_batch_lacking_corrected]    Script Date: 30/07/2025 12:27:44 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[Stock_Batch_correction_final_w_batch_lacking_corrected](
	[Store Code] [varchar](50) NULL,
	[Item number] [varchar](50) NULL,
	[Item Name] [varchar](254) NULL,
	[ref] [varchar](354) NULL,
	[Site] [varchar](50) NULL,
	[Warehouse] [varchar](50) NULL,
	[Location] [varchar](50) NULL,
	[Old Batch number] [varchar](50) NULL,
	[Sales qty] [decimal](38, 2) NULL,
	[New_Batch] [varchar](50) NULL,
	[Batch number] [varchar](50) NULL,
	[Available physical] [varchar](50) NULL,
	[New_Qty] [decimal](38, 2) NULL,
	[dIFF] [decimal](38, 2) NULL,
	[Expiry Date] [varchar](50) NULL,
	[Unit] [varchar](50) NULL,
	[all Batch On Hand] [nvarchar](max) NULL,
	[REMARKS] [varchar](50) NULL
) ON [PRIMARY] TEXTIMAGE_ON [PRIMARY]
GO
/****** Object:  View [dbo].[Stock_Batch_correction_final_2nd_pass]    Script Date: 30/07/2025 12:27:44 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO





/****** Script for SelectTopNRows command from SSMS  ******/
create view [dbo].[Stock_Batch_correction_final_2nd_pass]
as
SELECT [Store Code]
      ,[Item number]
      ,[Item Name]
      ,[Site]
      ,[Warehouse]
      ,[Location]
      ,[Old Batch number]
      ,[New_Batch]
      ,[New_Qty]
      ,[Expiry Date]
      ,[Unit]
      ,[Sales qty]
      ,[Old Available qty]
      ,[New Available qty]
      ,[found batch]
      ,[all Batch On Hand]
      ,[Remarks]
  FROM [MarinaDynamics365].[dbo].[Stock_Batch_correction_final_v2]
  where remarks in ('Batch Corrected')

  union 
  SELECT [Store Code]
      ,[Item number]
      ,[Item Name]
       ,[Site]
      ,[Warehouse]
      ,[Location]
      ,[Old Batch number]
       ,[Batch number]
      ,[Available physical]
	     ,[Expiry Date]
		 ,[Unit]
		   ,[Sales qty]
		     ,'0'[Old Available qty]
			  ,'0' [New Available qty]
			    ,'0'[found batch]
 ,[all Batch On Hand]
     
     
      ,case when [REMARKS]='with batch but not enough Stocks' then 'Batch Allocated and corrected'
	  when remarks='batch to add' then 'Need to add this batch' end 
  FROM [MarinaDynamics365].[dbo].[Stock_Batch_correction_final_w_batch_lacking_corrected]

  union

  SELECT [Store Code]
      ,[Item number]
      ,[Item Name]
       ,[Site]
      ,[Warehouse]
      ,[Location]
      ,[Old Batch number]
 ,[New_Batch]
      ,'0' [Available physical]
	     ,[Expiry Date]
		 ,[Unit]
		   ,[Sales qty]
		     ,'0'[Old Available qty]
			  ,'0' [New Available qty]
			    ,'0'[found batch]
 ,[all Batch On Hand]
     
    
      ,'Need to add this batch' [REMARKS]
  FROM [MarinaDynamics365].[dbo].[vw_Stock_Batch_correction_final_no_batch_no_stocks]
      union 
  SELECT [Store Code]
      ,[Item number]
      ,[Item Name]
       ,[Site]
      ,[Warehouse]
      ,[Location]
      ,[Old Batch number]
       ,[Batch number]
      ,[Available physical]
	     ,[Expiry Date]
		 ,[Unit]
		   ,[Sales qty]
		     ,'0'[Old Available qty]
			  ,[Available physical] [New Available qty]
			    ,'0'[found batch]
 ,[all Batch On Hand]
     
     
      ,case when [REMARKS]='other batch with enough Stocks' then 'Batch Allocated and corrected more stocks'
	  when remarks='batch to add' then 'Need to add this batch' end 
  FROM [MarinaDynamics365].[dbo].[Stock_Batch_correction_final_w_batch_more_Stocks_corrected]
  where  [Old Batch number]<> [Batch number]
GO
/****** Object:  View [dbo].[vw_StockIn_template]    Script Date: 30/07/2025 12:27:44 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO


create view [dbo].[vw_StockIn_template]
as
SELECT 

	'' JOURNALNUMBER	
	, [Item number] ITEMNUMBER
	  ,S.[Store Code] INVENTORYSITEID
   ,S.[Store Code] INVENTORYWAREHOUSEID
   ,   [Old Batch number] ITEMBATCHNUMBER
  ,'Storage' WAREHOUSELOCATIONID	
  ,  ROW_NUMBER() OVER(ORDER BY  [Item number] ASC) LINENUMBER 
  ,''COSTAMOUNT
	,(SELECT [DEFAULTLEDGERDIMENSIONDISPLAYVALUE]
			FROM [MarinaDynamics365].[dbo].[vw_Product_LEDGERDIMENSION] L 
			WHERE L.[ITEM NUMBER] =S.[ITEM NUMBER] 
			AND L.[STORECODE]=S.[Site]) DEFAULTLEDGERDIMENSIONDISPLAYVALUE
	,case when cast([New_Qty] as decimal(8,2))=0 then  [Sales qty] else [New_Qty] end  INVENTORYQUANTITY
	,'IADJ' JOURNALNAMEID	
	 ,FORMAT(GETDATE(), 'M/dd/yyyy 00:00')  TRANSACTIONDATE
,''	  UNITCOST 
,1 UNITCOSTQUANTITY
 
  

 FROM [MarinaDynamics365].[dbo].[Stock_Batch_correction_final_2nd_pass] S
	  where case when REMARKS='Batch Corrected' and [Old Batch number]=[New_Batch] then 'Matching' else  REMARKS end='Need to add this batch'
GO
/****** Object:  View [dbo].[vw_TransferOrder_Pending_Sum_created]    Script Date: 30/07/2025 12:27:44 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO

CREATE VIEW [dbo].[vw_TransferOrder_Pending_Sum_created]
AS
SELECT        dbo.TransferOrderHeaders.ReceivingWarehouseId, dbo.TransferOrderLines.ItemNumber, SUM(dbo.TransferOrderLines.TransferQuantity) AS Pending_Qty
FROM            dbo.TransferOrderHeaders LEFT OUTER JOIN
                         dbo.TransferOrderLines ON dbo.TransferOrderHeaders.TransferOrderNumber = dbo.TransferOrderLines.TransferOrderNumber
WHERE        (dbo.TransferOrderHeaders.ShippingWarehouseId IN (N'WH0001', N'WH0002')) AND (dbo.TransferOrderHeaders.TransferOrderStatus IN (N'Created'))
GROUP BY dbo.TransferOrderHeaders.ReceivingWarehouseId, dbo.TransferOrderLines.ItemNumber
GO
/****** Object:  Table [dbo].[Negtaive sales]    Script Date: 30/07/2025 12:27:44 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[Negtaive sales](
	[Statement number] [varchar](50) NULL,
	[Store Code] [varchar](50) NULL,
	[Item number] [varchar](50) NULL,
	[Item Name] [varchar](254) NULL,
	[Site] [varchar](50) NULL,
	[Warehouse] [varchar](50) NULL,
	[Location] [varchar](50) NULL,
	[Batch number] [varchar](50) NULL,
	[Expiry Date] [varchar](50) NULL,
	[Unit] [varchar](50) NULL,
	[Sales qty] [varchar](50) NULL,
	[Available qty] [varchar](50) NULL
) ON [PRIMARY]
GO
/****** Object:  Table [dbo].[ON hand Stock3]    Script Date: 30/07/2025 12:27:44 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[ON hand Stock3](
	[Item number] [varchar](50) NULL,
	[Product name] [varchar](254) NULL,
	[Search name] [varchar](254) NULL,
	[Consignment item] [varchar](50) NULL,
	[Site] [varchar](50) NULL,
	[Warehouse] [varchar](50) NULL,
	[Batch number] [varchar](50) NULL,
	[Location] [varchar](50) NULL,
	[Warehouse name] [varchar](50) NULL,
	[Physical inventory] [varchar](50) NULL,
	[Physical reserved] [varchar](50) NULL,
	[Available physical] [varchar](50) NULL,
	[Available physical on exact dimensions] [varchar](50) NULL,
	[Ordered in total] [varchar](50) NULL,
	[On order] [varchar](50) NULL,
	[Ordered reserved] [varchar](50) NULL,
	[Available for reservation] [varchar](50) NULL,
	[Total available] [varchar](50) NULL,
	[Uses warehouse management processes] [varchar](50) NULL,
	[Product identification] [varchar](254) NULL
) ON [PRIMARY]
GO
/****** Object:  View [dbo].[vw_Stock_Batch_correction]    Script Date: 30/07/2025 12:27:44 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO




/****** Script for SelectTopNRows command from SSMS  ******/
create view [dbo].[vw_Stock_Batch_correction]
as
SELECT [Statement number]
      ,[Store Code]
      ,[Item number]
      ,[Item Name]
      ,[Site]
      ,[Warehouse]
      ,[Location]
      ,[Batch number]
      ,[Expiry Date]
      ,[Unit]
      ,[Sales qty]
      ,[Available qty]
	   ,substring((select [Batch number] + ' - ' + [Available physical]   + ' - '
				from [MarinaDynamics365].[dbo].[ON hand Stock3] o 
				where o.[Item number]=m.[Item number] and o.[Warehouse]=m.[Warehouse] and [Available physical]<>'0'
		--		order by cast([Available physical] as decimal(8,0))- cast([Sales qty] as decimal(8,0)) asc
				for xml path('')), 1, (len((select  [Batch number]  + ' - ' + [Available physical] + ' - '
				from [MarinaDynamics365].[dbo].[ON hand Stock3] o 
				where o.[Item number]=m.[Item number] and  o.[Warehouse]=m.[Warehouse] and [Available physical]<>'0'
		--		order by cast([Available physical] as decimal(8,0))-cast([Sales qty] as decimal(8,0)) asc
				for xml path(''))) - 1)) [On Hand]
  FROM [MarinaDynamics365].[dbo].[Negtaive sales] m


GO
/****** Object:  Table [dbo].[D365_Sales_Registers_from_PBi]    Script Date: 30/07/2025 12:27:44 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[D365_Sales_Registers_from_PBi](
	[InventoryLotId] [varchar](max) NULL,
	[RequestedReceiptDate] [datetime] NULL,
	[bill_time] [time](7) NULL,
	[transaction_date] [date] NULL,
	[SalesOrderLineStatus] [varchar](max) NULL,
	[Product Id] [varchar](max) NULL,
	[Batch Key] [varchar](max) NULL,
	[Contact No] [varchar](max) NULL,
	[Location Id] [varchar](max) NULL,
	[Gift Card No] [varchar](max) NULL,
	[Discount Amount] [numeric](18, 2) NULL,
	[Batch] [varchar](max) NULL,
	[Unit] [varchar](max) NULL,
	[Qty Sold] [numeric](18, 2) NULL,
	[CalculateLineAmount] [varchar](max) NULL,
	[LineDescription] [varchar](max) NULL,
	[Bill No] [varchar](max) NULL,
	[Discount %] [numeric](18, 2) NULL,
	[SalesPrice] [numeric](18, 2) NULL,
	[Line Number] [numeric](18, 2) NULL,
	[Source Details] [varchar](max) NULL,
	[Line Amount] [numeric](24, 6) NULL,
	[Tax Amount] [numeric](27, 8) NULL,
	[SalesPriceQuantity] [numeric](18, 2) NULL,
	[Tax Group] [varchar](max) NULL,
	[RequestedShippingDate] [datetime] NULL,
	[Member Address] [varchar](max) NULL,
	[Customer Id] [varchar](max) NULL,
	[Payment Mode] [varchar](max) NULL,
	[Salesman Id] [varchar](max) NULL,
	[Agent Name] [varchar](max) NULL,
	[Prepared by] [varchar](max) NULL,
	[Driver] [varchar](max) NULL,
	[Order source] [varchar](max) NULL,
	[Customer Group] [varchar](max) NULL,
	[With Insurance] [varchar](max) NULL,
	[Backend Customer Id] [varchar](max) NULL,
	[cost_amount_retail] [numeric](18, 2) NULL,
	[discount_reason] [varchar](max) NULL,
	[doctor_code] [varchar](max) NULL,
	[Retail Promo Cost] [float] NULL,
	[Retail Qty Sold] [numeric](20, 2) NULL,
	[Retail Price] [numeric](20, 2) NULL,
	[discount_offer_id] [varchar](max) NULL,
	[Discount Name] [varchar](max) NULL,
	[member_id] [int] NULL,
	[partner_name] [varchar](max) NULL,
	[DiscountOriginType] [varchar](max) NULL,
	[trx_id] [varchar](max) NULL,
	[ReceiptNumber] [varchar](max) NULL,
	[Card No] [varchar](20) NULL,
	[source_crm] [varchar](200) NULL,
	[insurance_claim_no] [varchar](250) NULL,
	[insurance_card_no] [varchar](250) NULL
) ON [PRIMARY] TEXTIMAGE_ON [PRIMARY]
GO
/****** Object:  Table [dbo].[Mx_Preferred_List]    Script Date: 30/07/2025 12:27:44 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[Mx_Preferred_List](
	[ItemNumber] [varchar](50) NULL,
	[ProductName] [varchar](254) NULL,
	[BrandName] [varchar](254) NULL,
	[Remarks] [nchar](10) NULL
) ON [PRIMARY]
GO
/****** Object:  Table [dbo].[ProductCategoryAssignments]    Script Date: 30/07/2025 12:27:44 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[ProductCategoryAssignments](
	[ProductNumber] [nvarchar](max) NULL,
	[ProductCategoryName] [nvarchar](max) NULL,
	[ProductCategoryHierarchyName] [nvarchar](max) NULL,
	[DisplayOrder] [float] NULL
) ON [PRIMARY] TEXTIMAGE_ON [PRIMARY]
GO
/****** Object:  Table [dbo].[Workers]    Script Date: 30/07/2025 12:27:44 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[Workers](
	[PersonnelNumber] [int] NULL,
	[LastName] [varchar](255) NULL,
	[NameAlias] [varchar](255) NULL,
	[FirstName] [varchar](255) NULL,
	[Gender] [varchar](255) NULL,
	[Name] [varchar](255) NULL
) ON [PRIMARY]
GO
/****** Object:  View [dbo].[vw_Sales_Registers_Portal]    Script Date: 30/07/2025 12:27:44 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE VIEW [dbo].[vw_Sales_Registers_Portal]
AS
SELECT        CONVERT(varchar, dbo.D365_Sales_Registers_from_PBi.RequestedReceiptDate, 103) AS Date, dbo.D365_Sales_Registers_from_PBi.ReceiptNumber, dbo.D365_Sales_Registers_from_PBi.[Location Id], 
                         dbo.Workers.NameAlias AS SalesmanName, dbo.D365_Sales_Registers_from_PBi.[Line Number], dbo.D365_Sales_Registers_from_PBi.[Product Id], dbo.D365_Sales_Registers_from_PBi.LineDescription, 
                         dbo.D365_Sales_Registers_from_PBi.Unit, dbo.D365_Sales_Registers_from_PBi.[Qty Sold], dbo.D365_Sales_Registers_from_PBi.Batch, dbo.D365_Sales_Registers_from_PBi.SalesPrice, 
                         dbo.D365_Sales_Registers_from_PBi.[Discount Amount], dbo.D365_Sales_Registers_from_PBi.[Line Amount], dbo.D365_Sales_Registers_from_PBi.[Contact No], dbo.D365_Sales_Registers_from_PBi.[Customer Group], 
                         dbo.D365_Sales_Registers_from_PBi.[Discount Name], dbo.D365_Sales_Registers_from_PBi.[Bill No], dbo.ProductCategoryAssignments.ProductCategoryName AS Category, 
                         ProductCategoryAssignments_1.ProductCategoryName AS Brand, dbo.D365_Sales_Registers_from_PBi.RequestedReceiptDate, ISNULL(dbo.D365_Sales_Registers_from_PBi.[Retail Qty Sold], 0) AS [Retail Qty Sold], 
                         ISNULL(dbo.Mx_Preferred_List.BrandName, N'No') AS Preferred_List, CASE WHEN [Salesman Id] IN ('0527', '1310', '0003', '0965', '1498', '0028', '1107', '1133', '0053', '1395', '1649') 
                         THEN 'Yes' ELSE 'No' END AS CallCenter
FROM            dbo.D365_Sales_Registers_from_PBi LEFT OUTER JOIN
                         dbo.Mx_Preferred_List ON dbo.D365_Sales_Registers_from_PBi.[Product Id] = dbo.Mx_Preferred_List.ItemNumber LEFT OUTER JOIN
                         dbo.Workers ON dbo.D365_Sales_Registers_from_PBi.[Salesman Id] = dbo.Workers.PersonnelNumber LEFT OUTER JOIN
                         dbo.ProductCategoryAssignments AS ProductCategoryAssignments_1 ON dbo.D365_Sales_Registers_from_PBi.[Product Id] = ProductCategoryAssignments_1.ProductNumber LEFT OUTER JOIN
                         dbo.ProductCategoryAssignments ON dbo.D365_Sales_Registers_from_PBi.[Product Id] = dbo.ProductCategoryAssignments.ProductNumber
WHERE        (dbo.ProductCategoryAssignments.ProductCategoryHierarchyName = N'Marina_Old_Category') AND (ProductCategoryAssignments_1.ProductCategoryHierarchyName = N'Marina_Brand')
GO
/****** Object:  Table [dbo].[Mx_Min_Max_Raw_Upload]    Script Date: 30/07/2025 12:27:44 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[Mx_Min_Max_Raw_Upload](
	[ItemNumber] [varchar](50) NULL,
	[SiteCode] [varchar](50) NULL,
	[Min] [varchar](50) NULL,
	[Max] [varchar](50) NULL,
	[LastModifiedDate] [datetime] NULL,
	[LastModifiedBy] [varchar](50) NULL
) ON [PRIMARY]
GO
/****** Object:  Table [dbo].[PurchaseOrder_Status_sum]    Script Date: 30/07/2025 12:27:44 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[PurchaseOrder_Status_sum](
	[ItemNumber] [nvarchar](max) NULL,
	[OrderedPurchaseQuantity] [float] NULL,
	[Remaining] [float] NULL,
	[RequestedDeliveryDate] [datetime2](0) NULL
) ON [PRIMARY] TEXTIMAGE_ON [PRIMARY]
GO
/****** Object:  Table [dbo].[Mx_Product_Master_new_w_location]    Script Date: 30/07/2025 12:27:44 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[Mx_Product_Master_new_w_location](
	[ItemNumber] [nvarchar](max) NULL,
	[ProductName] [nvarchar](max) NULL,
	[ProductGroupId] [nvarchar](max) NULL,
	[RetailProductCategoryname] [nvarchar](max) NULL,
	[SalesSalesTaxItemGroupCode] [nvarchar](max) NULL,
	[Drug_id] [varchar](50) NULL,
	[STORECODE] [varchar](50) NULL,
	[LocationID] [varchar](50) NULL,
	[ShortName] [varchar](50) NULL,
	[Order_Group] [nvarchar](max) NULL
) ON [PRIMARY] TEXTIMAGE_ON [PRIMARY]
GO
/****** Object:  Table [dbo].[Lastest_Sales_per_item_Branch]    Script Date: 30/07/2025 12:27:44 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[Lastest_Sales_per_item_Branch](
	[Bill_No] [nvarchar](12) NOT NULL,
	[ItemNumber] [nchar](10) NULL,
	[Qty_Sold] [money] NULL,
	[LocationID] [int] NOT NULL,
	[Billdate] [datetime] NULL,
	[drug_id] [nvarchar](25) NOT NULL
) ON [PRIMARY]
GO
/****** Object:  Table [dbo].[Drug_Batch_Stock_ordered_SUM_PUR]    Script Date: 30/07/2025 12:27:44 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[Drug_Batch_Stock_ordered_SUM_PUR](
	[ItemNumber] [nvarchar](max) NULL,
	[Stock] [float] NULL,
	[Ordered] [float] NULL,
	[Drug_id] [varchar](50) NULL,
	[SiteID] [nvarchar](max) NULL,
	[LocationID] [varchar](50) NULL
) ON [PRIMARY] TEXTIMAGE_ON [PRIMARY]
GO
/****** Object:  View [dbo].[vw_Drug_Batch_Stock_ordered_SUM_PUR_WH]    Script Date: 30/07/2025 12:27:44 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO

CREATE VIEW [dbo].[vw_Drug_Batch_Stock_ordered_SUM_PUR_WH]
AS
SELECT        ItemNumber, sum(Stock) Stock, sum(Ordered) Ordered
FROM            dbo.Drug_Batch_Stock_ordered_SUM_PUR
WHERE        (LocationID IN ('35', '51'))
group by ItemNumber
GO
/****** Object:  Table [dbo].[Branch_Replenishment_itemnumberList]    Script Date: 30/07/2025 12:27:44 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[Branch_Replenishment_itemnumberList](
	[Column1] [varchar](50) NULL,
	[NewValue] [varchar](50) NULL
) ON [PRIMARY]
GO
/****** Object:  Table [dbo].[Branch_Replenishment_branch]    Script Date: 30/07/2025 12:27:44 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[Branch_Replenishment_branch](
	[Column1] [varchar](50) NULL,
	[NewValue] [varchar](50) NULL
) ON [PRIMARY]
GO
/****** Object:  Table [dbo].[TransferOrders_Latest_Received]    Script Date: 30/07/2025 12:27:44 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[TransferOrders_Latest_Received](
	[ShippingSiteId] [nvarchar](max) NULL,
	[ReceivingWarehouseId] [nvarchar](max) NULL,
	[ItemNumber] [nvarchar](max) NULL,
	[RequestedShippingDate] [datetime2](0) NULL,
	[RequestedReceiptDate] [datetime2](0) NULL,
	[ShippedQuantity] [float] NULL,
	[ReceivedQuantity] [float] NULL,
	[ItemBatchNumber] [nvarchar](max) NULL,
	[WH] [int] NULL
) ON [PRIMARY] TEXTIMAGE_ON [PRIMARY]
GO
/****** Object:  Table [dbo].[TransferOrderLines_Pending_InBR2WH_Transit_SUM]    Script Date: 30/07/2025 12:27:44 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[TransferOrderLines_Pending_InBR2WH_Transit_SUM](
	[ItemNumber] [nvarchar](max) NULL,
	[Qty] [float] NULL
) ON [PRIMARY] TEXTIMAGE_ON [PRIMARY]
GO
/****** Object:  Table [dbo].[Branch_Replenishment_Cons_Sum]    Script Date: 30/07/2025 12:27:44 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[Branch_Replenishment_Cons_Sum](
	[ItemNumber] [nchar](10) NULL,
	[LocationID] [int] NOT NULL,
	[Qty_Sold] [money] NULL
) ON [PRIMARY]
GO
/****** Object:  Table [dbo].[Branch_Replenishment_Max_QtySold]    Script Date: 30/07/2025 12:27:44 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[Branch_Replenishment_Max_QtySold](
	[ItemNumber] [nchar](10) NULL,
	[Max_Qty_Sold] [money] NULL,
	[LocationID] [int] NOT NULL
) ON [PRIMARY]
GO
/****** Object:  View [dbo].[vw_Branch_Replenisment_final_view_Items_Branch_selected]    Script Date: 30/07/2025 12:27:44 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO

    CREATE VIEW [dbo].[vw_Branch_Replenisment_final_view_Items_Branch_selected] AS
    SELECT 
        loc.STORECODE, 
        loc.ItemNumber, 
        loc.ShortName, 
        loc.ProductName, 
        loc.ProductGroupId, 
        ISNULL(brc.Qty_Sold, 0) AS Cos, 
        ISNULL(dbs.Stock, 0) AS Stock, 
        ISNULL(dbs.Ordered, 0) AS Intransit, 
        ISNULL(dbs.Stock, 0) + ISNULL(dbs.Ordered, 0) AS TotalStock, 
        ISNULL(wh.Stock, 0) AS WHStock, 
        ISNULL(wh.Ordered, 0) AS WHInTransit, 
        round(ISNULL(brc.Qty_Sold, 0) / 122 * 60 
            - (ISNULL(dbs.Stock, 0) + ISNULL(dbs.Ordered, 0)),0) AS Req_Order, 
			      ISNULL(brc.Qty_Sold, 0) / 122 * 60 
            - (ISNULL(dbs.Stock, 0) + ISNULL(dbs.Ordered, 0)) AS Req_Order_raw, 

        pm.Selling_Price, 
        ISNULL(brm.Max_Qty_Sold, 0) AS MaxQtySold, 
        ISNULL(tolr.ReceivedQuantity, 0) AS Last_Rec_Qty, 
        tolr.RequestedReceiptDate AS Last_Rec_Date,
        60 AS [Req. Days],
	          ISNULL(dbo.Mx_Min_Max_Raw_Upload.Min, '0') AS Min, ISNULL(dbo.Mx_Min_Max_Raw_Upload.Max, '0') AS Max
			    , dbo.Lastest_Sales_per_item_Branch.Billdate AS Last_Sales_date, 
                         dbo.Lastest_Sales_per_item_Branch.Qty_Sold AS Last_Sales_qty
						  , dbo.TransferOrderLines_Pending_InBR2WH_Transit_SUM.Qty as br2wh_Instransit
						  , dbo.PurchaseOrder_Status_sum.RequestedDeliveryDate AS Pending_LPO_Date
						  , ISNULL(dbo.PurchaseOrder_Status_sum.OrderedPurchaseQuantity, 0) AS Pending_LPO_Qty
						    , ISNULL(dbo.PurchaseOrder_Status_sum.Remaining, 0) AS Pending_LPO_Qty_Lacking
				

    FROM 
        dbo.Mx_Product_Master_new_w_location AS loc
        INNER JOIN dbo.Mx_PriceMaster AS pm ON loc.ItemNumber = pm.Item
		
		 LEFT OUTER JOIN
                         dbo.PurchaseOrder_Status_sum ON loc.ItemNumber = dbo.PurchaseOrder_Status_sum.ItemNumber
		LEFT OUTER JOIN
                         dbo.TransferOrderLines_Pending_InBR2WH_Transit_SUM ON loc.ItemNumber = dbo.TransferOrderLines_Pending_InBR2WH_Transit_SUM.ItemNumber
		LEFT OUTER JOIN
                         dbo.Lastest_Sales_per_item_Branch ON loc.ItemNumber = dbo.Lastest_Sales_per_item_Branch.ItemNumber AND loc.LocationID = dbo.Lastest_Sales_per_item_Branch.LocationID 

		LEFT OUTER JOIN
                         dbo.Mx_Min_Max_Raw_Upload ON loc.ItemNumber = dbo.Mx_Min_Max_Raw_Upload.ItemNumber AND loc.STORECODE = dbo.Mx_Min_Max_Raw_Upload.SiteCode 
        LEFT JOIN dbo.TransferOrders_Latest_Received AS tolr 
            ON loc.ItemNumber = tolr.ItemNumber 
            AND loc.STORECODE = tolr.ReceivingWarehouseId
        LEFT JOIN dbo.Branch_Replenishment_Max_QtySold AS brm 
            ON loc.ItemNumber = brm.ItemNumber 
            AND loc.LocationID = brm.LocationID
        LEFT JOIN dbo.vw_Drug_Batch_Stock_ordered_SUM_PUR_WH AS wh 
            ON loc.ItemNumber = wh.ItemNumber
        LEFT JOIN dbo.Drug_Batch_Stock_ordered_SUM_PUR AS dbs 
            ON loc.ItemNumber = dbs.ItemNumber 
            AND loc.LocationID = dbs.LocationID
        LEFT JOIN dbo.Branch_Replenishment_Cons_Sum AS brc 
            ON loc.ItemNumber = brc.ItemNumber 
            AND loc.LocationID = brc.LocationID
    WHERE 
        loc.STORECODE NOT IN ('WH0001', 'WH0002')
        AND loc.ItemNumber in ( SELECT  [Column1]
     
  FROM [MarinaDynamics365].[dbo].[Branch_Replenishment_itemnumberList])

 AND loc.ShortName in ( SELECT  [Column1]
     
  FROM [MarinaDynamics365].[dbo].[Branch_Replenishment_branch]);
    
GO
/****** Object:  Table [dbo].[EcoResCategoryBiEntities]    Script Date: 30/07/2025 12:27:44 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[EcoResCategoryBiEntities](
	[Name] [nvarchar](max) NULL,
	[CategoryHierarchy] [bigint] NULL,
	[NestedSetRight] [bigint] NULL,
	[SysCreatedBy] [nvarchar](max) NULL,
	[SysModifiedBy] [nvarchar](max) NULL,
	[SysRecVersion] [bigint] NULL,
	[ForceFullLookupSync] [nvarchar](max) NULL,
	[ServiceAccountingCodeTable_IN] [bigint] NULL,
	[SourceKey] [bigint] NULL,
	[DefaultThreshold_PSN] [float] NULL,
	[NestedSetLeft] [bigint] NULL,
	[IsTangible] [nvarchar](max) NULL,
	[IsActive] [nvarchar](max) NULL,
	[ParentCategory] [bigint] NULL,
	[IsCategoryAttributesInherited] [nvarchar](max) NULL,
	[NonGST_IN] [nvarchar](max) NULL,
	[InstanceRelationType] [bigint] NULL,
	[DisplayOrder] [float] NULL,
	[Exempt_IN] [nvarchar](max) NULL,
	[ExternalId] [nvarchar](max) NULL,
	[HSNCodeTable_IN] [bigint] NULL,
	[Code] [nvarchar](max) NULL,
	[Level] [bigint] NULL,
	[ChangeStatus] [nvarchar](max) NULL,
	[PKWiUCode] [nvarchar](max) NULL,
	[SysModifiedDateTime] [datetime2](0) NULL,
	[CreatedOn] [datetime2](0) NULL,
	[DefaultProjectGlobalCategory] [bigint] NULL,
	[ReuseEnabled] [nvarchar](max) NULL
) ON [PRIMARY] TEXTIMAGE_ON [PRIMARY]
GO
/****** Object:  Table [dbo].[EcoResCategoryHierarchyBiEntities]    Script Date: 30/07/2025 12:27:44 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[EcoResCategoryHierarchyBiEntities](
	[Name] [nvarchar](max) NULL,
	[SysRecVersion] [bigint] NULL,
	[SysModifiedBy] [nvarchar](max) NULL,
	[SysCreatedBy] [nvarchar](max) NULL,
	[SourceKey] [bigint] NULL,
	[SysModifiedDateTime] [datetime2](0) NULL,
	[HierarchyModifier] [nvarchar](max) NULL,
	[CreatedOn] [datetime2](0) NULL
) ON [PRIMARY] TEXTIMAGE_ON [PRIMARY]
GO
/****** Object:  View [dbo].[vw_Mx_BrandNames]    Script Date: 30/07/2025 12:27:44 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE VIEW [dbo].[vw_Mx_BrandNames]
AS
SELECT        dbo.EcoResCategoryHierarchyBiEntities.Name AS HierarchyName, dbo.EcoResCategoryBiEntities.Name AS BrandName
FROM            dbo.EcoResCategoryBiEntities LEFT OUTER JOIN
                         dbo.EcoResCategoryHierarchyBiEntities ON dbo.EcoResCategoryBiEntities.CategoryHierarchy = dbo.EcoResCategoryHierarchyBiEntities.SourceKey
GO
/****** Object:  View [dbo].[vw_Mx_PriceMaster2]    Script Date: 30/07/2025 12:27:44 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE VIEW [dbo].[vw_Mx_PriceMaster2]
AS
SELECT        p.Item, pm_new.Drug_id AS Drug_ID, pm.DrugName AS DrugName, CAST(MAX(p.[Amount in transaction currency]) AS decimal(8, 2)) AS Selling_Price, p.[Account selection]
FROM            dbo.PriceMaster_UploadRaw AS p LEFT OUTER JOIN
                         dbo.Mx_Product_Master_new AS pm_new ON pm_new.ItemNumber = p.Item LEFT OUTER JOIN
                         dbo.Mx_Product_Master AS pm ON pm.[Item number] = p.Item
WHERE        (p.[Account selection] = 'UAE-RETAIL') AND (p.Unit <> 'Pcs')
GROUP BY p.Item, pm_new.Drug_id, pm.DrugName, p.[Account selection]
GO
/****** Object:  Table [dbo].[HSInventSums]    Script Date: 30/07/2025 12:27:44 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[HSInventSums](
	[ItemId] [nvarchar](max) NULL,
	[InventDim_InventSiteId] [nvarchar](max) NULL,
	[InventDim_wMSLocationId] [nvarchar](max) NULL,
	[inventBatchId] [nvarchar](max) NULL,
	[AvailPhysical] [float] NULL,
	[Ordered] [float] NULL,
	[LastUpdate] [datetime2](0) NULL
) ON [PRIMARY] TEXTIMAGE_ON [PRIMARY]
GO
/****** Object:  View [dbo].[vw_Drug_Batch_Stock_ordered_SUM]    Script Date: 30/07/2025 12:27:44 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO










create view [dbo].[vw_Drug_Batch_Stock_ordered_SUM]
as

 SELECT        dbo.HSInventSums.ItemId AS ItemNumber, sum(dbo.HSInventSums.AvailPhysical) AS Stock, SUM(dbo.HSInventSums.Ordered) AS Ordered, dbo.Mx_Product_Master_new.Drug_id, 
                         dbo.HSInventSums.InventDim_InventSiteId AS SiteID, dbo.Mx_StoreCode.LocationID
FROM            dbo.HSInventSums LEFT OUTER JOIN
                         dbo.Mx_StoreCode ON dbo.HSInventSums.InventDim_InventSiteId = dbo.Mx_StoreCode.STORECODE LEFT OUTER JOIN
                         dbo.Mx_Product_Master_new ON dbo.HSInventSums.ItemId = dbo.Mx_Product_Master_new.ItemNumber
GROUP BY dbo.Mx_Product_Master_new.Drug_id, dbo.HSInventSums.InventDim_InventSiteId, dbo.Mx_StoreCode.LocationID, dbo.HSInventSums.InventDim_wMSLocationId
, dbo.HSInventSums.ItemId
HAVING        (dbo.HSInventSums.InventDim_wMSLocationId = N'Storage')


GO
/****** Object:  View [dbo].[vw_Mx_Stocks_by_Location_V2]    Script Date: 30/07/2025 12:27:44 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO


CREATE VIEW [dbo].[vw_Mx_Stocks_by_Location_V2]
AS
SELECT        dbo.Mx_Product_Master_new_w_location.ItemNumber, dbo.Mx_Product_Master_new_w_location.ProductName, dbo.Mx_Product_Master_new_w_location.STORECODE, dbo.Mx_Product_Master_new_w_location.ShortName, 
                         ISNULL(dbo.vw_Drug_Batch_Stock_ordered_SUM.Stock,0) as Stock, dbo.Mx_Product_Master_new_w_location.STORECODE + '-' +dbo.Mx_Product_Master_new_w_location.ShortName AS Site2, dbo.Mx_Product_Master_new_w_location.Drug_id
FROM            dbo.Mx_Product_Master_new_w_location LEFT OUTER JOIN
                         dbo.vw_Drug_Batch_Stock_ordered_SUM ON dbo.Mx_Product_Master_new_w_location.ItemNumber = dbo.vw_Drug_Batch_Stock_ordered_SUM.ItemNumber AND 
                         dbo.Mx_Product_Master_new_w_location.LocationID = dbo.vw_Drug_Batch_Stock_ordered_SUM.Locationid
GO
/****** Object:  View [dbo].[vw_Drug_Batch_Stock_ordered_SUM_temp]    Script Date: 30/07/2025 12:27:44 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO



create view [dbo].[vw_Drug_Batch_Stock_ordered_SUM_temp]
as
SELECT [Product Id] ItemNumber
,(Select Drug_id  FROM [MarinaDynamics365].[dbo].[Mx_Product_Master_new] dm
where dm.ItemNumber=i.[Product Id]) Drug_id
   
      ,sum([Available Qty]) Stock
	   ,sum([Ordered]) Ordered
 
      ,[Location Id] SiteID
	  ,(select Locationid from [MarinaDynamics365].dbo.Mx_StoreCode s
	  where s.STORECODE=i.[Location Id]) Locationid
   
  FROM [192.168.70.86].[crm_reports].[dbo].[fInventory] i
  where [Type Of Location]='Storage'

  group by [Product Id]
  ,[Location Id] 

GO
/****** Object:  Table [dbo].[PurchaseOrder_Open_Raw]    Script Date: 30/07/2025 12:27:44 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[PurchaseOrder_Open_Raw](
	[Vendor account] [varchar](50) NULL,
	[Purchase order] [varchar](50) NULL,
	[Line number] [varchar](50) NULL,
	[Item number] [varchar](50) NULL,
	[Requested receipt date] [varchar](50) NULL,
	[Quantity] [varchar](50) NULL,
	[Deliver remainder] [varchar](50) NULL,
	[Warehouse] [varchar](50) NULL
) ON [PRIMARY]
GO
/****** Object:  View [dbo].[vw_PurchaseOrder_Lacking]    Script Date: 30/07/2025 12:27:44 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO

create view [dbo].[vw_PurchaseOrder_Lacking]
as

SELECT [Purchase order] [PurchaseOrderNumber]
	,[Item number] ItemNumber
    , [Warehouse] SiteCode
    ,[Line number] [LineNumber]
  	   ,cast([Quantity] as int) [Ordered]
	   ,cast([Quantity] as int)-cast([Deliver remainder] as int) Delivered
      ,cast([Deliver remainder] as int) Lacking
      
  FROM [MarinaDynamics365].[dbo].[PurchaseOrder_Open_Raw]
 
  



GO
/****** Object:  Table [dbo].[Drug_Batch_Stock_ordered_SUM]    Script Date: 30/07/2025 12:27:44 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[Drug_Batch_Stock_ordered_SUM](
	[ItemNumber] [nvarchar](max) NULL,
	[Stock] [float] NULL,
	[Ordered] [float] NULL,
	[Drug_id] [varchar](50) NULL,
	[SiteID] [nvarchar](max) NULL,
	[LocationID] [varchar](50) NULL
) ON [PRIMARY] TEXTIMAGE_ON [PRIMARY]
GO
/****** Object:  View [dbo].[vw_MX_Product_MinMax_Price_Vendor_Stock_re_order_no_CONS]    Script Date: 30/07/2025 12:27:44 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE VIEW [dbo].[vw_MX_Product_MinMax_Price_Vendor_Stock_re_order_no_CONS]
AS
SELECT        dbo.Mx_Product_Master_new_w_location.ItemNumber, dbo.Mx_Product_Master_new_w_location.ProductName, dbo.Mx_Product_Master_new_w_location.ProductGroupId, 
                         dbo.Mx_Product_Master_new_w_location.RetailProductCategoryname, dbo.Mx_Product_Master_new_w_location.SalesSalesTaxItemGroupCode, dbo.Mx_Product_Master_new_w_location.Drug_id, 
                         dbo.Mx_Product_Master_new_w_location.STORECODE, dbo.Mx_Product_Master_new_w_location.LocationID, dbo.Mx_Product_Master_new_w_location.ShortName, ISNULL(dbo.Mx_Min_Max_Raw_Upload.Min, '0') AS Min, 
                         ISNULL(dbo.Mx_Min_Max_Raw_Upload.Max, '0') AS Max, dbo.MX_Product_Cost_SPrice_Upload_Raw.Price2 AS Cost, dbo.MX_Product_Cost_SPrice_Upload_Raw.Price, dbo.MX_Product_Cost_SPrice_Upload_Raw.Vendor, 
                         ISNULL(dbo.Drug_Batch_Stock_ordered_SUM.Stock, 0) AS Stock, ISNULL(dbo.vw_TransferOrder_Pending_Sum.Pending_Qty, 0) AS Pending_Stock, ISNULL(Drug_Batch_Stock_ordered_SUM_1.Ordered, 0) AS Ordered
FROM            dbo.Mx_Product_Master_new_w_location INNER JOIN
                         dbo.MX_Product_Cost_SPrice_Upload_Raw ON dbo.Mx_Product_Master_new_w_location.ItemNumber = dbo.MX_Product_Cost_SPrice_Upload_Raw.[Item number] INNER JOIN
                         dbo.Drug_Batch_Stock_ordered_SUM AS Drug_Batch_Stock_ordered_SUM_1 ON dbo.Mx_Product_Master_new_w_location.ItemNumber = Drug_Batch_Stock_ordered_SUM_1.ItemNumber AND 
                         dbo.Mx_Product_Master_new_w_location.STORECODE = Drug_Batch_Stock_ordered_SUM_1.SiteID LEFT OUTER JOIN
                         dbo.vw_TransferOrder_Pending_Sum ON dbo.Mx_Product_Master_new_w_location.STORECODE = dbo.vw_TransferOrder_Pending_Sum.ReceivingWarehouseId AND 
                         dbo.Mx_Product_Master_new_w_location.ItemNumber = dbo.vw_TransferOrder_Pending_Sum.ItemNumber LEFT OUTER JOIN
                         dbo.Drug_Batch_Stock_ordered_SUM ON dbo.Mx_Product_Master_new_w_location.ItemNumber = dbo.Drug_Batch_Stock_ordered_SUM.ItemNumber AND 
                         dbo.Mx_Product_Master_new_w_location.STORECODE = dbo.Drug_Batch_Stock_ordered_SUM.SiteID LEFT OUTER JOIN
                         dbo.Mx_Min_Max_Raw_Upload ON dbo.Mx_Product_Master_new_w_location.ItemNumber = dbo.Mx_Min_Max_Raw_Upload.ItemNumber AND 
                         dbo.Mx_Product_Master_new_w_location.STORECODE = dbo.Mx_Min_Max_Raw_Upload.SiteCode
GO
/****** Object:  Table [dbo].[Negtaive_sales_final]    Script Date: 30/07/2025 12:27:44 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[Negtaive_sales_final](
	[Store Code] [varchar](50) NULL,
	[Item number] [varchar](50) NULL,
	[Item Name] [varchar](254) NULL,
	[Site] [varchar](50) NULL,
	[Warehouse] [varchar](50) NULL,
	[Location] [varchar](50) NULL,
	[Batch number] [varchar](8000) NULL,
	[Expiry Date] [varchar](50) NULL,
	[Unit] [varchar](50) NULL,
	[Sales qty1] [decimal](38, 2) NULL,
	[Available qty] [decimal](18, 2) NULL,
	[Sales qty] [decimal](38, 2) NULL,
	[ref] [varchar](100) NULL,
	[Seq] [bigint] NULL,
	[Line_Count] [int] NULL
) ON [PRIMARY]
GO
/****** Object:  View [dbo].[vw_Negtaive_sales_final_sum]    Script Date: 30/07/2025 12:27:44 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
/****** Script for SelectTopNRows command from SSMS  ******/

CREATE VIEW [dbo].[vw_Negtaive_sales_final_sum]
as
SELECT [Store Code]
     
      ,[Item number]
	  ,[Store Code]
      + [Item number] ref
      
      ,SUM([Sales qty]) sum_qty
  FROM [MarinaDynamics365].[dbo].[Negtaive_sales_final]
  GROUP BY [Store Code]
    ,[Item number]
GO
/****** Object:  View [dbo].[vw_Stock_Batch_correction_final]    Script Date: 30/07/2025 12:27:44 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO



create view [dbo].[vw_Stock_Batch_correction_final]

as

SELECT [Statement number]
      ,[Store Code]
      ,[Item number]
      ,[Item Name]
      ,[Site]
      ,[Warehouse]
      ,[Location]
      ,[Batch number] [Old Batch number]
	
	  ,case when (select count([Batch number])
				from [MarinaDynamics365].[dbo].[ON hand Stock3] o 
				where o.[Item number]=m.[Item number] and o.[Warehouse]=m.[Warehouse] and [Available physical]<>'0'
				and cast([Available physical]as decimal(8,2))-cast([Sales qty] as decimal(8,2)) >=0) = 1
			
			then 
				(select [Batch number]
				from [MarinaDynamics365].[dbo].[ON hand Stock3] o 
				where o.[Item number]=m.[Item number] and o.[Warehouse]=m.[Warehouse] and [Available physical]<>'0'
				and cast([Available physical] as decimal(8,2))-cast([Sales qty] as decimal(8,2)) >=0 )

			 when (select count([Batch number])
				from [MarinaDynamics365].[dbo].[ON hand Stock3] o 
				where o.[Item number]=m.[Item number] and o.[Warehouse]=m.[Warehouse] and [Available physical]<>'0'
				and cast([Available physical]as decimal(8,2))-cast([Sales qty] as decimal(8,2)) >=0) > 1


				then (select top 1 [Batch number] 
				from [MarinaDynamics365].[dbo].[ON hand Stock3] o 
				where o.[Item number]=m.[Item number] and o.[Warehouse]=m.[Warehouse] and [Available physical]<>'0'
				and cast([Available physical] as decimal(8,2))-cast([Sales qty] as decimal(8,2)) >=0 
				order by cast([Available physical] as decimal(8,2))- cast([Sales qty] as decimal(8,2)) asc)



				end [New_Batch]

		 ,case when (select count([Batch number])
				from [MarinaDynamics365].[dbo].[ON hand Stock3] o 
				where o.[Item number]=m.[Item number] and o.[Warehouse]=m.[Warehouse] and [Available physical]<>'0'
				and cast([Available physical]as decimal(8,2))-cast([Sales qty] as decimal(8,2)) >=0) = 1
			
			then 
				(select [Available physical]
				from [MarinaDynamics365].[dbo].[ON hand Stock3] o 
				where o.[Item number]=m.[Item number] and o.[Warehouse]=m.[Warehouse] and [Available physical]<>'0'
				and cast([Available physical] as decimal(8,2))-cast([Sales qty] as decimal(8,2)) >=0 )

			 when (select count([Batch number])
				from [MarinaDynamics365].[dbo].[ON hand Stock3] o 
				where o.[Item number]=m.[Item number] and o.[Warehouse]=m.[Warehouse] and [Available physical]<>'0'
				and cast([Available physical]as decimal(8,2))-cast([Sales qty] as decimal(8,2)) >=0) > 1


				then (select top 1 [Available physical]
				from [MarinaDynamics365].[dbo].[ON hand Stock3] o 
				where o.[Item number]=m.[Item number] and o.[Warehouse]=m.[Warehouse] and [Available physical]<>'0'
				and cast([Available physical] as decimal(8,2))-cast([Sales qty] as decimal(8,2)) >=0 
				order by cast([Available physical] as decimal(8,2))- cast([Sales qty] as decimal(8,2)) asc)



				end [New_Qty]
				 

				 


     
      



      ,[Expiry Date]
      ,[Unit]
      ,[Sales qty]
      ,[Available qty]  [Old Available qty] 
	    ,case when (select count([Batch number])
				from [MarinaDynamics365].[dbo].[ON hand Stock3] o 
				where o.[Item number]=m.[Item number] and o.[Warehouse]=m.[Warehouse] and [Available physical]<>'0'
				and cast([Available physical]as decimal(8,2))-cast([Sales qty] as decimal(8,2)) >=0) = 1
			
			then 
				(select cast([Available physical] as decimal(8,2))
				from [MarinaDynamics365].[dbo].[ON hand Stock3] o 
				where o.[Item number]=m.[Item number] and o.[Warehouse]=m.[Warehouse] and [Available physical]<>'0'
				and cast([Available physical] as decimal(8,2))-cast([Sales qty] as decimal(8,2)) >=0 )

			 when (select count([Batch number])
				from [MarinaDynamics365].[dbo].[ON hand Stock3] o 
				where o.[Item number]=m.[Item number] and o.[Warehouse]=m.[Warehouse] and [Available physical]<>'0'
				and cast([Available physical]as decimal(8,2))-cast([Sales qty] as decimal(8,2)) >=0) > 1


				then (select top 1 cast([Available physical] as decimal(8,2))
				from [MarinaDynamics365].[dbo].[ON hand Stock3] o 
				where o.[Item number]=m.[Item number] and o.[Warehouse]=m.[Warehouse] and [Available physical]<>'0'
				and cast([Available physical] as decimal(8,2))-cast([Sales qty] as decimal(8,2)) >=0 
				order by cast([Available physical] as decimal(8,2))- cast([Sales qty] as decimal(8,2)) asc)



				end [New Available qty]


	     ,(select count([Batch number])
				from [MarinaDynamics365].[dbo].[ON hand Stock3] o 
				where o.[Item number]=m.[Item number] and o.[Warehouse]=m.[Warehouse] and [Available physical]<>'0'
				and cast([Available physical]as decimal(8,2))-cast([Sales qty] as decimal(8,2)) >=0) [found batch]

	

	,substring((select [Batch number] + ' - ' + [Available physical]   + ' - '
				from [MarinaDynamics365].[dbo].[ON hand Stock3] o 
				where o.[Item number]=m.[Item number] and o.[Warehouse]=m.[Warehouse] and [Available physical]<>'0'
			
				order by cast([Available physical] as decimal(8,2))- cast([Sales qty] as decimal(8,2)) asc
				for xml path('')), 1, 
				
				(len((select  [Batch number]  + ' - ' + [Available physical] + ' - '
				from [MarinaDynamics365].[dbo].[ON hand Stock3] o 
				where o.[Item number]=m.[Item number] and  o.[Warehouse]=m.[Warehouse] and [Available physical]<>'0'
				
			order by cast([Available physical] as decimal(8,2))-cast([Sales qty] as decimal(8,2)) asc
				for xml path(''))) - 1)) [all Batch On Hand]

  ,case when (select count([Batch number])
				from [MarinaDynamics365].[dbo].[ON hand Stock3] o 
				where o.[Item number]=m.[Item number] and o.[Warehouse]=m.[Warehouse] and [Available physical]<>'0'
				and cast([Available physical]as decimal(8,2))-cast([Sales qty] as decimal(8,2)) >=0) = 1
			
			then 
				'Batch Corrected'

			 when (select count([Batch number])
				from [MarinaDynamics365].[dbo].[ON hand Stock3] o 
				where o.[Item number]=m.[Item number] and o.[Warehouse]=m.[Warehouse] and [Available physical]<>'0'
				and cast([Available physical]as decimal(8,2))-cast([Sales qty] as decimal(8,2)) >=0) > 1


			then	'Batch Corrected'


	when (select count([Batch number])
				from [MarinaDynamics365].[dbo].[ON hand Stock3] o 
				where o.[Item number]=m.[Item number] and o.[Warehouse]=m.[Warehouse] and [Available physical]<>'0'
				and cast([Available physical]as decimal(8,2))-cast([Sales qty] as decimal(8,2)) >=0) = 0

				and
				isnull(
				(select top 1 [Batch number] + ' - ' + [Available physical]   + ' - '
				from [MarinaDynamics365].[dbo].[ON hand Stock3] o 
				where o.[Item number]=m.[Item number] and o.[Warehouse]=m.[Warehouse] and [Available physical]<>'0'),'x')
				='x'

				then 'No batch and no stocks'
			

			when (select count([Batch number])
				from [MarinaDynamics365].[dbo].[ON hand Stock3] o 
				where o.[Item number]=m.[Item number] and o.[Warehouse]=m.[Warehouse] and [Available physical]<>'0'
				and cast([Available physical]as decimal(8,2))-cast([Sales qty] as decimal(8,2)) >=0) = 0

				and
				isnull(
				(select top 1 [Batch number] + ' - ' + [Available physical]   + ' - '
				from [MarinaDynamics365].[dbo].[ON hand Stock3] o 
				where o.[Item number]=m.[Item number] and o.[Warehouse]=m.[Warehouse] and [Available physical]<>'0'),'x')
				<>'x'

				then 'with batch but no enough Stocks'

				
				end [Remarks]
				 

       
	   
	   FROM [MarinaDynamics365].[dbo].[Negtaive sales] m


GO
/****** Object:  View [dbo].[vw_Drug_Batch_Stock_ordered_SUM_Branch_Total]    Script Date: 30/07/2025 12:27:44 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO











create view [dbo].[vw_Drug_Batch_Stock_ordered_SUM_Branch_Total]
as

 SELECT        dbo.HSInventSums.ItemId AS ItemNumber, sum(dbo.HSInventSums.AvailPhysical) AS Stock, SUM(dbo.HSInventSums.Ordered) AS Ordered
FROM            dbo.HSInventSums LEFT OUTER JOIN
                         dbo.Mx_StoreCode ON dbo.HSInventSums.InventDim_InventSiteId = dbo.Mx_StoreCode.STORECODE LEFT OUTER JOIN
                         dbo.Mx_Product_Master_new ON dbo.HSInventSums.ItemId = dbo.Mx_Product_Master_new.ItemNumber
						 where dbo.Mx_StoreCode.LocationID not in (35,51)
GROUP BY  dbo.HSInventSums.ItemId,dbo.HSInventSums.InventDim_wMSLocationId
HAVING        (dbo.HSInventSums.InventDim_wMSLocationId = N'Storage') 


GO
/****** Object:  View [dbo].[vw_Stock_Batch_correction_final_v2_orig]    Script Date: 30/07/2025 12:27:44 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO








create view [dbo].[vw_Stock_Batch_correction_final_v2_orig]

as

SELECT [Store Code]
      ,[Item number]
      ,[Item Name]
      ,[Site]
      ,[Warehouse]
      ,[Location]
      ,[Batch number] [Old Batch number]
	
	  ,case when (select count([Batch number])
				from [MarinaDynamics365].[dbo].[ON hand Stock3] o 
				where o.[Item number]=m.[Item number] and o.[Warehouse]=m.[Warehouse] and [Available physical]<>'0'
				and cast([Available physical]as decimal(8,2))-cast([Sales qty] as decimal(8,2)) >=0) = 1
			
			then 
				(select [Batch number]
				from [MarinaDynamics365].[dbo].[ON hand Stock3] o 
				where o.[Item number]=m.[Item number] and o.[Warehouse]=m.[Warehouse] and [Available physical]<>'0'
				and cast([Available physical] as decimal(8,2))-cast([Sales qty] as decimal(8,2)) >=0 )

			 when (select count([Batch number])
				from [MarinaDynamics365].[dbo].[ON hand Stock3] o 
				where o.[Item number]=m.[Item number] and o.[Warehouse]=m.[Warehouse] and [Available physical]<>'0'
				and cast([Available physical]as decimal(8,2))-cast([Sales qty] as decimal(8,2)) >=0) > 1


				then (select top 1 [Batch number] 
				from [MarinaDynamics365].[dbo].[ON hand Stock3] o 
				where o.[Item number]=m.[Item number] and o.[Warehouse]=m.[Warehouse] and [Available physical]<>'0'
				and cast([Available physical] as decimal(8,2))-cast([Sales qty] as decimal(8,2)) >=0 
				order by cast([Available physical] as decimal(8,2))- cast([Sales qty] as decimal(8,2)) asc)



				end [New_Batch]

		 ,case when (select count([Batch number])
				from [MarinaDynamics365].[dbo].[ON hand Stock3] o 
				where o.[Item number]=m.[Item number] and o.[Warehouse]=m.[Warehouse] and [Available physical]<>'0'
				and cast([Available physical]as decimal(8,2))-cast([Sales qty] as decimal(8,2)) >=0) = 1
			
			then 
				(select [Available physical]
				from [MarinaDynamics365].[dbo].[ON hand Stock3] o 
				where o.[Item number]=m.[Item number] and o.[Warehouse]=m.[Warehouse] and [Available physical]<>'0'
				and cast([Available physical] as decimal(8,2))-cast([Sales qty] as decimal(8,2)) >=0 )

			 when (select count([Batch number])
				from [MarinaDynamics365].[dbo].[ON hand Stock3] o 
				where o.[Item number]=m.[Item number] and o.[Warehouse]=m.[Warehouse] and [Available physical]<>'0'
				and cast([Available physical]as decimal(8,2))-cast([Sales qty] as decimal(8,2)) >=0) > 1


				then (select top 1 [Available physical]
				from [MarinaDynamics365].[dbo].[ON hand Stock3] o 
				where o.[Item number]=m.[Item number] and o.[Warehouse]=m.[Warehouse] and [Available physical]<>'0'
				and cast([Available physical] as decimal(8,2))-cast([Sales qty] as decimal(8,2)) >=0 
				order by cast([Available physical] as decimal(8,2))- cast([Sales qty] as decimal(8,2)) asc)



				end [New_Qty]
				 

				 


     
      



      ,[Expiry Date]
      ,[Unit]
      ,[Sales qty]
      ,[Available qty]  [Old Available qty] 
	    ,case when (select count([Batch number])
				from [MarinaDynamics365].[dbo].[ON hand Stock3] o 
				where o.[Item number]=m.[Item number] and o.[Warehouse]=m.[Warehouse] and [Available physical]<>'0'
				and cast([Available physical]as decimal(8,2))-cast([Sales qty] as decimal(8,2)) >=0) = 1
			
			then 
				(select cast([Available physical] as decimal(8,2))
				from [MarinaDynamics365].[dbo].[ON hand Stock3] o 
				where o.[Item number]=m.[Item number] and o.[Warehouse]=m.[Warehouse] and [Available physical]<>'0'
				and cast([Available physical] as decimal(8,2))-cast([Sales qty] as decimal(8,2)) >=0 )

			 when (select count([Batch number])
				from [MarinaDynamics365].[dbo].[ON hand Stock3] o 
				where o.[Item number]=m.[Item number] and o.[Warehouse]=m.[Warehouse] and [Available physical]<>'0'
				and cast([Available physical]as decimal(8,2))-cast([Sales qty] as decimal(8,2)) >=0) > 1


				then (select top 1 cast([Available physical] as decimal(8,2))
				from [MarinaDynamics365].[dbo].[ON hand Stock3] o 
				where o.[Item number]=m.[Item number] and o.[Warehouse]=m.[Warehouse] and [Available physical]<>'0'
				and cast([Available physical] as decimal(8,2))-cast([Sales qty] as decimal(8,2)) >=0 
				order by cast([Available physical] as decimal(8,2))- cast([Sales qty] as decimal(8,2)) asc)



				end [New Available qty]


	     ,(select count([Batch number])
				from [MarinaDynamics365].[dbo].[ON hand Stock3] o 
				where o.[Item number]=m.[Item number] and o.[Warehouse]=m.[Warehouse] and [Available physical]<>'0'
				and cast([Available physical]as decimal(8,2))-cast([Sales qty] as decimal(8,2)) >=0) [found batch]

	

	,substring((select [Batch number] + ' - ' + [Available physical]   + ' - '
				from [MarinaDynamics365].[dbo].[ON hand Stock3] o 
				where o.[Item number]=m.[Item number] and o.[Warehouse]=m.[Warehouse] and [Available physical]<>'0'
			
				order by cast([Available physical] as decimal(8,2))- cast([Sales qty] as decimal(8,2)) asc
				for xml path('')), 1, 
				
				(len((select  [Batch number]  + ' - ' + [Available physical] + ' - '
				from [MarinaDynamics365].[dbo].[ON hand Stock3] o 
				where o.[Item number]=m.[Item number] and  o.[Warehouse]=m.[Warehouse] and [Available physical]<>'0'
				
			order by cast([Available physical] as decimal(8,2))-cast([Sales qty] as decimal(8,2)) asc
				for xml path(''))) - 1)) [all Batch On Hand]

  ,case 
  
			when (select count([Batch number])
				from [MarinaDynamics365].[dbo].[ON hand Stock3] o 
				where o.[Item number]=m.[Item number] and o.[Warehouse]=m.[Warehouse] and [Available physical]<>'0'
				and cast([Available physical]as decimal(8,2))-cast([Sales qty] as decimal(8,2)) >=0) = 1
			
			then 
				'Batch Corrected'

			 when (select count([Batch number])
				from [MarinaDynamics365].[dbo].[ON hand Stock3] o 
				where o.[Item number]=m.[Item number] and o.[Warehouse]=m.[Warehouse] and [Available physical]<>'0'
				and cast([Available physical]as decimal(8,2))-cast([Sales qty] as decimal(8,2)) >=0) > 1


			then	'Batch Corrected'


	when (select count([Batch number])
				from [MarinaDynamics365].[dbo].[ON hand Stock3] o 
				where o.[Item number]=m.[Item number] and o.[Warehouse]=m.[Warehouse] and [Available physical]<>'0'
				and cast([Available physical]as decimal(8,2))-cast([Sales qty] as decimal(8,2)) >=0) = 0

				and
				isnull(
				(select top 1 [Batch number] + ' - ' + [Available physical]   + ' - '
				from [MarinaDynamics365].[dbo].[ON hand Stock3] o 
				where o.[Item number]=m.[Item number] and o.[Warehouse]=m.[Warehouse] and [Available physical]<>'0'),'x')
				='x'

				then 'No batch and no stocks'
			
	when (select count([Batch number])
				from [MarinaDynamics365].[dbo].[ON hand Stock3] o 
				where o.[Item number]=m.[Item number] and o.[Warehouse]=m.[Warehouse] and [Available physical]<>'0'
				and cast([Available physical]as decimal(8,2))-cast([Sales qty] as decimal(8,2)) >=0) = 0

				and
			
			   isnull(
				(select top 1 [Batch number] + ' - ' + [Available physical]   + ' - '
				from [MarinaDynamics365].[dbo].[ON hand Stock3] o 
				where o.[Item number]=m.[Item number] and o.[Warehouse]=m.[Warehouse] and [Available physical]<>'0'),'x')
				<>'x'

				and
				(select sum(cast([Available physical]as decimal(8,2)))
				from [MarinaDynamics365].[dbo].[ON hand Stock3] o 
				where o.[Item number]=m.[Item number] and o.[Warehouse]=m.[Warehouse] and [Available physical]<>'0')
				<

				cast([Sales qty] as decimal(8,2)) 

				then 'with batch but not enough Stocks'


				
			when (select count([Batch number])
				from [MarinaDynamics365].[dbo].[ON hand Stock3] o 
				where o.[Item number]=m.[Item number] and o.[Warehouse]=m.[Warehouse] and [Available physical]<>'0'
				and cast([Available physical]as decimal(8,2))-cast([Sales qty] as decimal(8,2)) >=0) =0

				and
			
			   isnull(
				(select top 1 [Batch number] + ' - ' + [Available physical]   + ' - '
				from [MarinaDynamics365].[dbo].[ON hand Stock3] o 
				where o.[Item number]=m.[Item number] and o.[Warehouse]=m.[Warehouse] and [Available physical]<>'0'),'x')
				<>'x'

					and
				(select sum(cast([Available physical]as decimal(8,2)))
				from [MarinaDynamics365].[dbo].[ON hand Stock3] o 
				where o.[Item number]=m.[Item number] and o.[Warehouse]=m.[Warehouse] and [Available physical]<>'0')
				>=

				cast([Sales qty] as decimal(8,2)) 


				then 'other batch with enough Stocks'


				
				end [Remarks]
				 

       
	   
	   FROM [MarinaDynamics365].[dbo].[Negtaive_sales_final] m


GO
/****** Object:  View [dbo].[vw_FEB2024_MinMax_Order_Branch_Final_ALL_WH_MIN]    Script Date: 30/07/2025 12:27:44 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO














create view [dbo].[vw_FEB2024_MinMax_Order_Branch_Final_ALL_WH_MIN]
as

SELECT [ItemNumber]
      ,[ProductName]
      ,[ProductGroupId]
      ,[RetailProductCategoryname]
      ,[SalesSalesTaxItemGroupCode]
      ,[Drug_id]
      ,[STORECODE]
      ,[LocationID]
      ,[ShortName]
      ,cast([Min] as int) [Min]
      ,cast([Max] as int) [Max]
      ,[Cost]
      ,[Price]
      ,[Vendor]
      ,floor([Stock]) [Stock]
      ,[Pending_Stock]
	-- , [dbo].[CalCulateOrder]([ItemNumber],[LocationID],(floor([Stock])-floor(Unposted_Qty))+([Pending_Stock]-TR_Pending) ,[Min],[Max]) [Order]
	  , [dbo].[CalCulateOrder]([ItemNumber],[LocationID],floor([Stock])+([Pending_Stock]-TR_Pending) ,[Min],[Max]) [Order]
	  --  , [dbo].[CalCulateOrder_by_Max]([ItemNumber],[LocationID],floor([Stock])+([Pending_Stock]-TR_Pending) ,[Max]) [Order]
	  ,floor(CONS) CONS
	  ,TR_Pending
	  ,Unposted_Qty
	  ,order_group
  FROM [MarinaDynamics365].[dbo].[MX_Product_MinMax_Price_Vendor_Stock]
  where  CONS+[Min]+[Max]+[Stock]<>0
  and [STORECODE] not in ('WH0001','WH0002')
GO
/****** Object:  Table [dbo].[D365_fConsumption]    Script Date: 30/07/2025 12:27:44 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[D365_fConsumption](
	[RequestedReceiptDate] [date] NULL,
	[ItemNumber] [varchar](250) NULL,
	[ShippingWarehouseId] [varchar](250) NULL,
	[SalesUnitSymbol] [varchar](250) NULL,
	[OrderedSalesQuantity] [float] NULL
) ON [PRIMARY]
GO
/****** Object:  View [dbo].[D365_vw_Sales_Registers]    Script Date: 30/07/2025 12:27:44 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE VIEW [dbo].[D365_vw_Sales_Registers]
AS
SELECT        dbo.D365_fConsumption.ShippingWarehouseId, dbo.Mx_StoreCode.STORENAME, dbo.D365_fConsumption.RequestedReceiptDate, dbo.D365_fConsumption.ItemNumber, dbo.Mx_Product_Master_new.ProductName, 
                         dbo.Mx_Product_Master_new.PurchaseUnitSymbol, dbo.Mx_Product_Master_new.BOMUnitSymbol, dbo.Mx_Product_Master_new.SalesSalesTaxItemGroupCode, dbo.Mx_Product_Master_new.Drug_id, 
                         dbo.Mx_Product_Master_new.ProductGroupId, dbo.Mx_Product_Master_new.RetailProductCategoryname, dbo.D365_fConsumption.SalesUnitSymbol, dbo.D365_fConsumption.OrderedSalesQuantity, 
                         dbo.Mx_Product_Master_new.Factor, 
                         CASE WHEN dbo.D365_fConsumption.SalesUnitSymbol = 'Pcs' THEN dbo.D365_fConsumption.OrderedSalesQuantity / dbo.Mx_Product_Master_new.Factor ELSE dbo.D365_fConsumption.OrderedSalesQuantity END AS Qty_Sold,
                          dbo.Mx_StoreCode.LocationID, dbo.Mx_StoreCode.ShortName
FROM            dbo.D365_fConsumption LEFT OUTER JOIN
                         dbo.Mx_StoreCode ON dbo.D365_fConsumption.ShippingWarehouseId = dbo.Mx_StoreCode.STORECODE LEFT OUTER JOIN
                         dbo.Mx_Product_Master_new ON dbo.D365_fConsumption.ItemNumber = dbo.Mx_Product_Master_new.ItemNumber
WHERE        (dbo.D365_fConsumption.ShippingWarehouseId <> 'Courier') AND (dbo.D365_fConsumption.ItemNumber NOT IN ('102880', '102604', '103658', '102605', '108379', '110488', '111555', '108378', '102605', '102880', '103658', 
                         '108378', '110717', '114316', 'GIFTCARD'))
GO
/****** Object:  View [dbo].[vw_Stock_Batch_correction_final_v2_2]    Script Date: 30/07/2025 12:27:44 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO








create view [dbo].[vw_Stock_Batch_correction_final_v2_2]

as

SELECT [Store Code]
      ,[Item number]
      ,[Item Name]
      ,[Site]
      ,[Warehouse]
      ,[Location]
      ,[Batch number] [Old Batch number]
	
	  ,case when (select count([Batch number])
				from [MarinaDynamics365].[dbo].[ON hand Stock3] o 
				where o.[Item number]=m.[Item number] and o.[Warehouse]=m.[Warehouse] and [Available physical]<>'0'
				and cast([Available physical]as decimal(8,2))-cast([Sales qty] as decimal(8,2)) >=0) = 1
			
			then 
				(select [Batch number]
				from [MarinaDynamics365].[dbo].[ON hand Stock3] o 
				where o.[Item number]=m.[Item number] and o.[Warehouse]=m.[Warehouse] and [Available physical]<>'0'
				and cast([Available physical] as decimal(8,2))-cast([Sales qty] as decimal(8,2)) >=0 )

			 when (select count([Batch number])
				from [MarinaDynamics365].[dbo].[ON hand Stock3] o 
				where o.[Item number]=m.[Item number] and o.[Warehouse]=m.[Warehouse] and [Available physical]<>'0'
				and cast([Available physical]as decimal(8,2))-cast([Sales qty] as decimal(8,2)) >=0) > 1


				then (select top 1 [Batch number] 
				from [MarinaDynamics365].[dbo].[ON hand Stock3] o 
				where o.[Item number]=m.[Item number] and o.[Warehouse]=m.[Warehouse] and [Available physical]<>'0'
				and cast([Available physical] as decimal(8,2))-cast([Sales qty] as decimal(8,2)) >=0 
				order by cast([Available physical] as decimal(8,2))- cast([Sales qty] as decimal(8,2)) asc)



				end [New_Batch]

		 ,case when (select count([Batch number])
				from [MarinaDynamics365].[dbo].[ON hand Stock3] o 
				where o.[Item number]=m.[Item number] and o.[Warehouse]=m.[Warehouse] and [Available physical]<>'0'
				and cast([Available physical]as decimal(8,2))-cast([Sales qty] as decimal(8,2)) >=0) = 1
			
			then 
				(select [Available physical]
				from [MarinaDynamics365].[dbo].[ON hand Stock3] o 
				where o.[Item number]=m.[Item number] and o.[Warehouse]=m.[Warehouse] and [Available physical]<>'0'
				and cast([Available physical] as decimal(8,2))-cast([Sales qty] as decimal(8,2)) >=0 )

			 when (select count([Batch number])
				from [MarinaDynamics365].[dbo].[ON hand Stock3] o 
				where o.[Item number]=m.[Item number] and o.[Warehouse]=m.[Warehouse] and [Available physical]<>'0'
				and cast([Available physical]as decimal(8,2))-cast([Sales qty] as decimal(8,2)) >=0) > 1


				then (select top 1 [Available physical]
				from [MarinaDynamics365].[dbo].[ON hand Stock3] o 
				where o.[Item number]=m.[Item number] and o.[Warehouse]=m.[Warehouse] and [Available physical]<>'0'
				and cast([Available physical] as decimal(8,2))-cast([Sales qty] as decimal(8,2)) >=0 
				order by cast([Available physical] as decimal(8,2))- cast([Sales qty] as decimal(8,2)) asc)



				end [New_Qty]
				 

				 


     
      



      ,[Expiry Date]
      ,[Unit]
      ,[Sales qty]
      ,[Available qty]  [Old Available qty] 
	    ,case when (select count([Batch number])
				from [MarinaDynamics365].[dbo].[ON hand Stock3] o 
				where o.[Item number]=m.[Item number] and o.[Warehouse]=m.[Warehouse] and [Available physical]<>'0'
				and cast([Available physical]as decimal(8,2))-cast([Sales qty] as decimal(8,2)) >=0) = 1
			
			then 
				(select cast([Available physical] as decimal(8,2))
				from [MarinaDynamics365].[dbo].[ON hand Stock3] o 
				where o.[Item number]=m.[Item number] and o.[Warehouse]=m.[Warehouse] and [Available physical]<>'0'
				and cast([Available physical] as decimal(8,2))-cast([Sales qty] as decimal(8,2)) >=0 )

			 when (select count([Batch number])
				from [MarinaDynamics365].[dbo].[ON hand Stock3] o 
				where o.[Item number]=m.[Item number] and o.[Warehouse]=m.[Warehouse] and [Available physical]<>'0'
				and cast([Available physical]as decimal(8,2))-cast([Sales qty] as decimal(8,2)) >=0) > 1


				then (select top 1 cast([Available physical] as decimal(8,2))
				from [MarinaDynamics365].[dbo].[ON hand Stock3] o 
				where o.[Item number]=m.[Item number] and o.[Warehouse]=m.[Warehouse] and [Available physical]<>'0'
				and cast([Available physical] as decimal(8,2))-cast([Sales qty] as decimal(8,2)) >=0 
				order by cast([Available physical] as decimal(8,2))- cast([Sales qty] as decimal(8,2)) asc)



				end [New Available qty]


	     ,(select count([Batch number])
				from [MarinaDynamics365].[dbo].[ON hand Stock3] o 
				where o.[Item number]=m.[Item number] and o.[Warehouse]=m.[Warehouse] and [Available physical]<>'0'
				and cast([Available physical]as decimal(8,2))-cast([Sales qty] as decimal(8,2)) >=0) [found batch]

	

	,substring((select [Batch number] + ' - ' + [Available physical]   + ' - '
				from [MarinaDynamics365].[dbo].[ON hand Stock3] o 
				where o.[Item number]=m.[Item number] and o.[Warehouse]=m.[Warehouse] and [Available physical]<>'0'
			
				order by cast([Available physical] as decimal(8,2))- cast([Sales qty] as decimal(8,2)) asc
				for xml path('')), 1, 
				
				(len((select  [Batch number]  + ' - ' + [Available physical] + ' - '
				from [MarinaDynamics365].[dbo].[ON hand Stock3] o 
				where o.[Item number]=m.[Item number] and  o.[Warehouse]=m.[Warehouse] and [Available physical]<>'0'
				
			order by cast([Available physical] as decimal(8,2))-cast([Sales qty] as decimal(8,2)) asc
				for xml path(''))) - 1)) [all Batch On Hand]

  ,case 
  
			when (select count([Batch number])
				from [MarinaDynamics365].[dbo].[ON hand Stock3] o 
				where o.[Item number]=m.[Item number] and o.[Warehouse]=m.[Warehouse] and [Available physical]<>'0'
				and cast([Available physical]as decimal(8,2))-cast([Sales qty] as decimal(8,2)) >=0) = 1
			
			then 
				'Batch Corrected'

			 when (select count([Batch number])
				from [MarinaDynamics365].[dbo].[ON hand Stock3] o 
				where o.[Item number]=m.[Item number] and o.[Warehouse]=m.[Warehouse] and [Available physical]<>'0'
				and cast([Available physical]as decimal(8,2))-cast([Sales qty] as decimal(8,2)) >=0) > 1


			then	'Batch Corrected'


	when (select count([Batch number])
				from [MarinaDynamics365].[dbo].[ON hand Stock3] o 
				where o.[Item number]=m.[Item number] and o.[Warehouse]=m.[Warehouse] and [Available physical]<>'0'
				and cast([Available physical]as decimal(8,2))-cast([Sales qty] as decimal(8,2)) >=0) = 0

				and
				isnull(
				(select top 1 [Batch number] + ' - ' + [Available physical]   + ' - '
				from [MarinaDynamics365].[dbo].[ON hand Stock3] o 
				where o.[Item number]=m.[Item number] and o.[Warehouse]=m.[Warehouse] and [Available physical]<>'0'),'x')
				='x'

				then 'No batch and no stocks'
			
	when (select count([Batch number])
				from [MarinaDynamics365].[dbo].[ON hand Stock3] o 
				where o.[Item number]=m.[Item number] and o.[Warehouse]=m.[Warehouse] and [Available physical]<>'0'
				and cast([Available physical]as decimal(8,2))-cast([Sales qty] as decimal(8,2)) >=0) = 0

				and
			
			   isnull(
				(select top 1 [Batch number] + ' - ' + [Available physical]   + ' - '
				from [MarinaDynamics365].[dbo].[ON hand Stock3] o 
				where o.[Item number]=m.[Item number] and o.[Warehouse]=m.[Warehouse] and [Available physical]<>'0'),'x')
				<>'x'

				and
				(select sum(cast([Available physical]as decimal(8,2)))
				from [MarinaDynamics365].[dbo].[ON hand Stock3] o 
				where o.[Item number]=m.[Item number] and o.[Warehouse]=m.[Warehouse] and [Available physical]<>'0')
				<

				cast([Sales qty] as decimal(8,2)) 

				then 'with batch but not enough Stocks'


				
			when (select count([Batch number])
				from [MarinaDynamics365].[dbo].[ON hand Stock3] o 
				where o.[Item number]=m.[Item number] and o.[Warehouse]=m.[Warehouse] and [Available physical]<>'0'
				and cast([Available physical]as decimal(8,2))-cast([Sales qty] as decimal(8,2)) >=0) =0

				and
			
			   isnull(
				(select top 1 [Batch number] + ' - ' + [Available physical]   + ' - '
				from [MarinaDynamics365].[dbo].[ON hand Stock3] o 
				where o.[Item number]=m.[Item number] and o.[Warehouse]=m.[Warehouse] and [Available physical]<>'0'),'x')
				<>'x'

					and
				(select sum(cast([Available physical]as decimal(8,2)))
				from [MarinaDynamics365].[dbo].[ON hand Stock3] o 
				where o.[Item number]=m.[Item number] and o.[Warehouse]=m.[Warehouse] and [Available physical]<>'0')
				>=

				cast([Sales qty] as decimal(8,2)) 


				then 'other batch with enough Stocks'


				
				end [Remarks]
				 

       
	   
	   FROM [MarinaDynamics365].[dbo].[Negtaive_sales_final] m


GO
/****** Object:  View [dbo].[vw_sum_stock_item_branch]    Script Date: 30/07/2025 12:27:44 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
create view [dbo].[vw_sum_stock_item_branch]
as

SELECT  [ItemId]
      ,[InventDim_InventSiteId]
      
      ,sum([AvailPhysical]) Stock
   
  FROM [MarinaDynamics365].[dbo].[HSInventSums]
 group by  [ItemId]
      ,[InventDim_InventSiteId]
GO
/****** Object:  View [dbo].[vw_Stock_Batch_correction_final_v2]    Script Date: 30/07/2025 12:27:44 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO








create view [dbo].[vw_Stock_Batch_correction_final_v2]

as

SELECT [Store Code]
      ,[Item number]
      ,[Item Name]
      ,[Site]
      ,[Warehouse]
      ,[Location]
      ,[Batch number] [Old Batch number]
	
	  ,case when (select count([Batch number])
				from [MarinaDynamics365].[dbo].[ON hand Stock3] o 
				where o.[Item number]=m.[Item number] and o.[Warehouse]=m.[Warehouse] and [Available physical]<>'0'
				and cast([Available physical]as decimal(8,2))-cast([Sales qty] as decimal(8,2)) >=0) = 1
			
			then 
				(select [Batch number]
				from [MarinaDynamics365].[dbo].[ON hand Stock3] o 
				where o.[Item number]=m.[Item number] and o.[Warehouse]=m.[Warehouse] and [Available physical]<>'0'
				and cast([Available physical] as decimal(8,2))-cast([Sales qty] as decimal(8,2)) >=0 )

			 when (select count([Batch number])
				from [MarinaDynamics365].[dbo].[ON hand Stock3] o 
				where o.[Item number]=m.[Item number] and o.[Warehouse]=m.[Warehouse] and [Available physical]<>'0'
				and cast([Available physical]as decimal(8,2))-cast([Sales qty] as decimal(8,2)) >=0) > 1


				then (select top 1 [Batch number] 
				from [MarinaDynamics365].[dbo].[ON hand Stock3] o 
				where o.[Item number]=m.[Item number] and o.[Warehouse]=m.[Warehouse] and [Available physical]<>'0'
				and cast([Available physical] as decimal(8,2))-cast([Sales qty] as decimal(8,2)) >=0 
				order by cast([Available physical] as decimal(8,2))- cast([Sales qty] as decimal(8,2)) asc)



				end [New_Batch]

		 ,case when (select count([Batch number])
				from [MarinaDynamics365].[dbo].[ON hand Stock3] o 
				where o.[Item number]=m.[Item number] and o.[Warehouse]=m.[Warehouse] and [Available physical]<>'0'
				and cast([Available physical]as decimal(8,2))-cast([Sales qty] as decimal(8,2)) >=0) = 1
			
			then 
				(select [Available physical]
				from [MarinaDynamics365].[dbo].[ON hand Stock3] o 
				where o.[Item number]=m.[Item number] and o.[Warehouse]=m.[Warehouse] and [Available physical]<>'0'
				and cast([Available physical] as decimal(8,2))-cast([Sales qty] as decimal(8,2)) >=0 )

			 when (select count([Batch number])
				from [MarinaDynamics365].[dbo].[ON hand Stock3] o 
				where o.[Item number]=m.[Item number] and o.[Warehouse]=m.[Warehouse] and [Available physical]<>'0'
				and cast([Available physical]as decimal(8,2))-cast([Sales qty] as decimal(8,2)) >=0) > 1


				then (select top 1 [Available physical]
				from [MarinaDynamics365].[dbo].[ON hand Stock3] o 
				where o.[Item number]=m.[Item number] and o.[Warehouse]=m.[Warehouse] and [Available physical]<>'0'
				and cast([Available physical] as decimal(8,2))-cast([Sales qty] as decimal(8,2)) >=0 
				order by cast([Available physical] as decimal(8,2))- cast([Sales qty] as decimal(8,2)) asc)



				end [New_Qty]
				 

				 


     
      



      ,[Expiry Date]
      ,[Unit]
      ,[Sales qty]
      ,[Available qty]  [Old Available qty] 
	    ,case when (select count([Batch number])
				from [MarinaDynamics365].[dbo].[ON hand Stock3] o 
				where o.[Item number]=m.[Item number] and o.[Warehouse]=m.[Warehouse] and [Available physical]<>'0'
				and cast([Available physical]as decimal(8,2))-cast([Sales qty] as decimal(8,2)) >=0) = 1
			
			then 
				(select cast([Available physical] as decimal(8,2))
				from [MarinaDynamics365].[dbo].[ON hand Stock3] o 
				where o.[Item number]=m.[Item number] and o.[Warehouse]=m.[Warehouse] and [Available physical]<>'0'
				and cast([Available physical] as decimal(8,2))-cast([Sales qty] as decimal(8,2)) >=0 )

			 when (select count([Batch number])
				from [MarinaDynamics365].[dbo].[ON hand Stock3] o 
				where o.[Item number]=m.[Item number] and o.[Warehouse]=m.[Warehouse] and [Available physical]<>'0'
				and cast([Available physical]as decimal(8,2))-cast([Sales qty] as decimal(8,2)) >=0) > 1


				then (select top 1 cast([Available physical] as decimal(8,2))
				from [MarinaDynamics365].[dbo].[ON hand Stock3] o 
				where o.[Item number]=m.[Item number] and o.[Warehouse]=m.[Warehouse] and [Available physical]<>'0'
				and cast([Available physical] as decimal(8,2))-cast([Sales qty] as decimal(8,2)) >=0 
				order by cast([Available physical] as decimal(8,2))- cast([Sales qty] as decimal(8,2)) asc)



				end [New Available qty]


	     ,(select count([Batch number])
				from [MarinaDynamics365].[dbo].[ON hand Stock3] o 
				where o.[Item number]=m.[Item number] and o.[Warehouse]=m.[Warehouse] and [Available physical]<>'0'
				and cast([Available physical]as decimal(8,2))-cast([Sales qty] as decimal(8,2)) >=0) [found batch]

	

	, '' [all Batch On Hand]

  ,case 
  
			when (select count([Batch number])
				from [MarinaDynamics365].[dbo].[ON hand Stock3] o 
				where o.[Item number]=m.[Item number] and o.[Warehouse]=m.[Warehouse] and [Available physical]<>'0'
				and cast([Available physical]as decimal(8,2))-cast([Sales qty] as decimal(8,2)) >=0) = 1
			
			then 
				'Batch Corrected'

			 when (select count([Batch number])
				from [MarinaDynamics365].[dbo].[ON hand Stock3] o 
				where o.[Item number]=m.[Item number] and o.[Warehouse]=m.[Warehouse] and [Available physical]<>'0'
				and cast([Available physical]as decimal(8,2))-cast([Sales qty] as decimal(8,2)) >=0) > 1


			then	'Batch Corrected'


	when (select count([Batch number])
				from [MarinaDynamics365].[dbo].[ON hand Stock3] o 
				where o.[Item number]=m.[Item number] and o.[Warehouse]=m.[Warehouse] and [Available physical]<>'0'
				and cast([Available physical]as decimal(8,2))-cast([Sales qty] as decimal(8,2)) >=0) = 0

				and
				isnull(
				(select top 1 [Batch number] + ' - ' + [Available physical]   + ' - '
				from [MarinaDynamics365].[dbo].[ON hand Stock3] o 
				where o.[Item number]=m.[Item number] and o.[Warehouse]=m.[Warehouse] and [Available physical]<>'0'),'x')
				='x'

				then 'No batch and no stocks'
			
	when (select count([Batch number])
				from [MarinaDynamics365].[dbo].[ON hand Stock3] o 
				where o.[Item number]=m.[Item number] and o.[Warehouse]=m.[Warehouse] and [Available physical]<>'0'
				and cast([Available physical]as decimal(8,2))-cast([Sales qty] as decimal(8,2)) >=0) = 0

				and
			
			   isnull(
				(select top 1 [Batch number] + ' - ' + [Available physical]   + ' - '
				from [MarinaDynamics365].[dbo].[ON hand Stock3] o 
				where o.[Item number]=m.[Item number] and o.[Warehouse]=m.[Warehouse] and [Available physical]<>'0'),'x')
				<>'x'

				and
				(select sum(cast([Available physical]as decimal(8,2)))
				from [MarinaDynamics365].[dbo].[ON hand Stock3] o 
				where o.[Item number]=m.[Item number] and o.[Warehouse]=m.[Warehouse] and [Available physical]<>'0')
				<

				cast([Sales qty] as decimal(8,2)) 

				then 'with batch but not enough Stocks'


				
			when (select count([Batch number])
				from [MarinaDynamics365].[dbo].[ON hand Stock3] o 
				where o.[Item number]=m.[Item number] and o.[Warehouse]=m.[Warehouse] and [Available physical]<>'0'
				and cast([Available physical]as decimal(8,2))-cast([Sales qty] as decimal(8,2)) >=0) =0

				and
			
			   isnull(
				(select top 1 [Batch number] + ' - ' + [Available physical]   + ' - '
				from [MarinaDynamics365].[dbo].[ON hand Stock3] o 
				where o.[Item number]=m.[Item number] and o.[Warehouse]=m.[Warehouse] and [Available physical]<>'0'),'x')
				<>'x'

					and
				(select sum(cast([Available physical]as decimal(8,2)))
				from [MarinaDynamics365].[dbo].[ON hand Stock3] o 
				where o.[Item number]=m.[Item number] and o.[Warehouse]=m.[Warehouse] and [Available physical]<>'0')
				>=

				cast([Sales qty] as decimal(8,2)) 


				then 'other batch with enough Stocks'


				
				end [Remarks]
				 

       
	   
	   FROM [MarinaDynamics365].[dbo].[Negtaive_sales_final] m


GO
/****** Object:  Table [dbo].[SALES_ZERO_STOCK_REF_COMBINED_60days]    Script Date: 30/07/2025 12:27:44 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[SALES_ZERO_STOCK_REF_COMBINED_60days](
	[ItemNumber] [nchar](10) NULL,
	[LocationID] [int] NOT NULL,
	[Qty_Sold] [money] NULL
) ON [PRIMARY]
GO
/****** Object:  Table [dbo].[Unposted_Sales_Invoice]    Script Date: 30/07/2025 12:27:44 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[Unposted_Sales_Invoice](
	[ItemNumber] [varchar](max) NULL,
	[SiteCode] [varchar](max) NULL,
	[Qty] [numeric](38, 2) NULL
) ON [PRIMARY] TEXTIMAGE_ON [PRIMARY]
GO
/****** Object:  Table [dbo].[UNPOSTED_ITEMS_Sum]    Script Date: 30/07/2025 12:27:44 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[UNPOSTED_ITEMS_Sum](
	[Branch_id] [varchar](50) NULL,
	[SKU] [varchar](50) NULL,
	[Qty_Unposted] [decimal](38, 2) NULL
) ON [PRIMARY]
GO
/****** Object:  View [dbo].[vw_UNPOSTED_ITEMS_Sum_for_ORder]    Script Date: 30/07/2025 12:27:44 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO

create view [dbo].[vw_UNPOSTED_ITEMS_Sum_for_ORder]
as

SELECT   dbo.UNPOSTED_ITEMS_Sum.SKU, dbo.UNPOSTED_ITEMS_Sum.Branch_id, 
dbo.UNPOSTED_ITEMS_Sum.Qty_Unposted, 
ISNULL(dbo.Drug_Batch_Stock_ordered_SUM.Stock, 0) AS Stock
,ISNULL(dbo.Drug_Batch_Stock_ordered_SUM.Stock, 0)-dbo.UNPOSTED_ITEMS_Sum.Qty_Unposted Diff
FROM  dbo.UNPOSTED_ITEMS_Sum LEFT OUTER JOIN
      dbo.Drug_Batch_Stock_ordered_SUM ON dbo.UNPOSTED_ITEMS_Sum.SKU = dbo.Drug_Batch_Stock_ordered_SUM.ItemNumber AND dbo.UNPOSTED_ITEMS_Sum.Branch_id = dbo.Drug_Batch_Stock_ordered_SUM.SiteID
	  where
	  ISNULL(dbo.Drug_Batch_Stock_ordered_SUM.Stock, 0)-dbo.UNPOSTED_ITEMS_Sum.Qty_Unposted >0
GO
/****** Object:  Table [dbo].[Mx_Product_Warehouse_Locations]    Script Date: 30/07/2025 12:27:44 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[Mx_Product_Warehouse_Locations](
	[ItemNumber] [varchar](50) NULL,
	[Warehouse] [varchar](50) NULL
) ON [PRIMARY]
GO
/****** Object:  View [dbo].[vw_MX_Product_MinMax_Price_Vendor_Stock_re_order]    Script Date: 30/07/2025 12:27:44 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE VIEW [dbo].[vw_MX_Product_MinMax_Price_Vendor_Stock_re_order]
AS
SELECT        dbo.Mx_Product_Master_new_w_location.ItemNumber, dbo.Mx_Product_Master_new_w_location.ProductName, dbo.Mx_Product_Master_new_w_location.ProductGroupId, 
                         dbo.Mx_Product_Master_new_w_location.RetailProductCategoryname, dbo.Mx_Product_Master_new_w_location.SalesSalesTaxItemGroupCode, dbo.Mx_Product_Master_new_w_location.Drug_id, 
                         dbo.Mx_Product_Master_new_w_location.STORECODE, dbo.Mx_Product_Master_new_w_location.LocationID, dbo.Mx_Product_Master_new_w_location.ShortName, ISNULL(dbo.Mx_Min_Max_Raw_Upload.Min, '0') AS Min, 
                         ISNULL(dbo.Mx_Min_Max_Raw_Upload.Max, '0') AS Max, dbo.MX_Product_Cost_SPrice_Upload_Raw.Price2 AS Cost, dbo.MX_Product_Cost_SPrice_Upload_Raw.Price, dbo.MX_Product_Cost_SPrice_Upload_Raw.Vendor, 
                         ISNULL(dbo.Drug_Batch_Stock_ordered_SUM.Stock, 0) AS Stock, ISNULL(dbo.SALES_ZERO_STOCK_REF_COMBINED_60days.Qty_Sold, 0) AS CONS, ISNULL(dbo.vw_TransferOrder_Pending_Sum.Pending_Qty, 0) 
                         AS Pending_Stock, ISNULL(Drug_Batch_Stock_ordered_SUM_1.Ordered, 0) AS Ordered, dbo.Unposted_Sales_Invoice.Qty AS Unposted_Qty, ISNULL(dbo.Mx_Product_Warehouse_Locations.Warehouse, 'MARINA') 
                         AS Warehouse, ISNULL(dbo.vw_UNPOSTED_ITEMS_Sum_for_ORder.Diff, ISNULL(dbo.Drug_Batch_Stock_ordered_SUM.Stock, 0)) AS Stock_after_Unposted, ISNULL(dbo.vw_UNPOSTED_ITEMS_Sum_for_ORder.Qty_Unposted, 
                         0) AS Qty_Unposted, ISNULL(dbo.vw_TransferOrder_Pending_Sum_created.Pending_Qty, 0) AS Pending_Qty_TO_Created
FROM            dbo.Mx_Product_Master_new_w_location LEFT OUTER JOIN
                         dbo.vw_TransferOrder_Pending_Sum_created ON dbo.Mx_Product_Master_new_w_location.STORECODE = dbo.vw_TransferOrder_Pending_Sum_created.ReceivingWarehouseId AND 
                         dbo.Mx_Product_Master_new_w_location.ItemNumber = dbo.vw_TransferOrder_Pending_Sum_created.ItemNumber LEFT OUTER JOIN
                         dbo.Drug_Batch_Stock_ordered_SUM AS Drug_Batch_Stock_ordered_SUM_1 ON dbo.Mx_Product_Master_new_w_location.ItemNumber = Drug_Batch_Stock_ordered_SUM_1.ItemNumber AND 
                         dbo.Mx_Product_Master_new_w_location.STORECODE = Drug_Batch_Stock_ordered_SUM_1.SiteID LEFT OUTER JOIN
                         dbo.vw_UNPOSTED_ITEMS_Sum_for_ORder ON dbo.Mx_Product_Master_new_w_location.STORECODE = dbo.vw_UNPOSTED_ITEMS_Sum_for_ORder.Branch_id AND 
                         dbo.Mx_Product_Master_new_w_location.ItemNumber = dbo.vw_UNPOSTED_ITEMS_Sum_for_ORder.SKU LEFT OUTER JOIN
                         dbo.Mx_Product_Warehouse_Locations ON dbo.Mx_Product_Master_new_w_location.ItemNumber = dbo.Mx_Product_Warehouse_Locations.ItemNumber LEFT OUTER JOIN
                         dbo.MX_Product_Cost_SPrice_Upload_Raw ON dbo.Mx_Product_Master_new_w_location.ItemNumber = dbo.MX_Product_Cost_SPrice_Upload_Raw.[Item number] LEFT OUTER JOIN
                         dbo.Unposted_Sales_Invoice ON dbo.Mx_Product_Master_new_w_location.ItemNumber = dbo.Unposted_Sales_Invoice.ItemNumber AND 
                         dbo.Mx_Product_Master_new_w_location.STORECODE = dbo.Unposted_Sales_Invoice.SiteCode LEFT OUTER JOIN
                         dbo.vw_TransferOrder_Pending_Sum ON dbo.Mx_Product_Master_new_w_location.STORECODE = dbo.vw_TransferOrder_Pending_Sum.ReceivingWarehouseId AND 
                         dbo.Mx_Product_Master_new_w_location.ItemNumber = dbo.vw_TransferOrder_Pending_Sum.ItemNumber LEFT OUTER JOIN
                         dbo.SALES_ZERO_STOCK_REF_COMBINED_60days ON dbo.Mx_Product_Master_new_w_location.ItemNumber = dbo.SALES_ZERO_STOCK_REF_COMBINED_60days.ItemNumber AND 
                         dbo.Mx_Product_Master_new_w_location.LocationID = dbo.SALES_ZERO_STOCK_REF_COMBINED_60days.LocationID LEFT OUTER JOIN
                         dbo.Drug_Batch_Stock_ordered_SUM ON dbo.Mx_Product_Master_new_w_location.ItemNumber = dbo.Drug_Batch_Stock_ordered_SUM.ItemNumber AND 
                         dbo.Mx_Product_Master_new_w_location.STORECODE = dbo.Drug_Batch_Stock_ordered_SUM.SiteID LEFT OUTER JOIN
                         dbo.Mx_Min_Max_Raw_Upload ON dbo.Mx_Product_Master_new_w_location.ItemNumber = dbo.Mx_Min_Max_Raw_Upload.ItemNumber AND 
                         dbo.Mx_Product_Master_new_w_location.STORECODE = dbo.Mx_Min_Max_Raw_Upload.SiteCode
GO
/****** Object:  Table [dbo].[PurchaseOrderHeadersV2]    Script Date: 30/07/2025 12:27:44 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[PurchaseOrderHeadersV2](
	[dataAreaId] [nvarchar](max) NULL,
	[PurchaseOrderNumber] [nvarchar](max) NULL,
	[ExpectedStoreAvailableSalesDate] [datetime2](0) NULL,
	[VendorInvoiceDeclarationId] [nvarchar](max) NULL,
	[DeliveryModeId] [nvarchar](max) NULL,
	[InvoiceAddressStreet] [nvarchar](max) NULL,
	[OrderVendorAccountNumber] [nvarchar](max) NULL,
	[Email] [nvarchar](max) NULL,
	[TransportationModeId] [nvarchar](max) NULL,
	[IsChangeManagementActive] [nvarchar](max) NULL,
	[AccountingDistributionTemplateName] [nvarchar](max) NULL,
	[DeliveryAddressDescription] [nvarchar](max) NULL,
	[VendorTransactionSettlementType] [nvarchar](max) NULL,
	[DeliveryCityInKana] [nvarchar](max) NULL,
	[DeliveryStreetInKana] [nvarchar](max) NULL,
	[ReasonComment] [nvarchar](max) NULL,
	[NumberSequenceGroupId] [nvarchar](max) NULL,
	[TransportationTemplateId] [nvarchar](max) NULL,
	[AccountingDate] [datetime2](0) NULL,
	[CashDiscountPercentage] [float] NULL,
	[PurchaseOrderName] [nvarchar](max) NULL,
	[RequestedDeliveryDate] [datetime2](0) NULL,
	[DeliveryAddressCountryRegionId] [nvarchar](max) NULL,
	[DeliveryAddressLatitude] [float] NULL,
	[MultilineDiscountVendorGroupCode] [nvarchar](max) NULL,
	[DeliveryAddressCity] [nvarchar](max) NULL,
	[ConfirmedDeliveryDate] [datetime2](0) NULL,
	[PurchaseRebateVendorGroupId] [nvarchar](max) NULL,
	[InvoiceAddressCounty] [nvarchar](max) NULL,
	[ChargeVendorGroupId] [nvarchar](max) NULL,
	[RequesterPersonnelNumber] [nvarchar](max) NULL,
	[ProjectId] [nvarchar](max) NULL,
	[ShippingCarrierId] [nvarchar](max) NULL,
	[TotalDiscountPercentage] [float] NULL,
	[DeliveryAddressDistrictName] [nvarchar](max) NULL,
	[PriceVendorGroupCode] [nvarchar](max) NULL,
	[PurchaseOrderHeaderCreationMethod] [nvarchar](max) NULL,
	[DeliveryAddressCountyId] [nvarchar](max) NULL,
	[DeliveryAddressZipCode] [nvarchar](max) NULL,
	[IsConsolidatedInvoiceTarget] [nvarchar](max) NULL,
	[ConfirmingPurchaseOrderCode] [nvarchar](max) NULL,
	[LanguageId] [nvarchar](max) NULL,
	[ReasonCode] [nvarchar](max) NULL,
	[DeliveryAddressDunsNumber] [nvarchar](max) NULL,
	[DeliveryTermsId] [nvarchar](max) NULL,
	[BankDocumentType] [nvarchar](max) NULL,
	[ExpectedStoreReceiptDate] [datetime2](0) NULL,
	[DeliveryAddressName] [nvarchar](max) NULL,
	[InvoiceAddressCountryRegionId] [nvarchar](max) NULL,
	[ReplenishmentServiceCategoryId] [nvarchar](max) NULL,
	[PurchaseOrderPoolId] [nvarchar](max) NULL,
	[DeliveryAddressStreetNumber] [nvarchar](max) NULL,
	[RequestedShipDate] [datetime2](0) NULL,
	[ExpectedCrossDockingDate] [datetime2](0) NULL,
	[InvoiceAddressStreetNumber] [nvarchar](max) NULL,
	[IsDeliveryAddressPrivate] [nvarchar](max) NULL,
	[TaxExemptNumber] [nvarchar](max) NULL,
	[FormattedInvoiceAddress] [nvarchar](max) NULL,
	[BuyerGroupId] [nvarchar](max) NULL,
	[DeliveryAddressCountryRegionISOCode] [nvarchar](max) NULL,
	[CashDiscountCode] [nvarchar](max) NULL,
	[PaymentScheduleName] [nvarchar](max) NULL,
	[IntrastatTransactionCode] [nvarchar](max) NULL,
	[URL] [nvarchar](max) NULL,
	[CurrencyCode] [nvarchar](max) NULL,
	[ConfirmingPurchaseOrderCodeLanguageId] [nvarchar](max) NULL,
	[InvoiceType] [nvarchar](max) NULL,
	[ArePricesIncludingSalesTax] [nvarchar](max) NULL,
	[DeliveryAddressLocationId] [nvarchar](max) NULL,
	[GSTSelfBilledInvoiceApprovalNumber] [nvarchar](max) NULL,
	[IsDeliveredDirectly] [nvarchar](max) NULL,
	[ConfirmedShipDate] [datetime2](0) NULL,
	[ShipCalendarId] [nvarchar](max) NULL,
	[IntrastatStatisticsProcedureCode] [nvarchar](max) NULL,
	[InvoiceVendorAccountNumber] [nvarchar](max) NULL,
	[OverrideSalesTax] [nvarchar](max) NULL,
	[DeliveryAddressStreet] [nvarchar](max) NULL,
	[VendorOrderReference] [nvarchar](max) NULL,
	[ReplenishmentWarehouseId] [nvarchar](max) NULL,
	[FixedDueDate] [datetime2](0) NULL,
	[TransportationDocumentLineId] [nvarchar](max) NULL,
	[SalesTaxGroupCode] [nvarchar](max) NULL,
	[IsDeliveryAddressOrderSpecific] [nvarchar](max) NULL,
	[VendorPostingProfileId] [nvarchar](max) NULL,
	[VendorPaymentMethodSpecificationName] [nvarchar](max) NULL,
	[InvoiceAddressCity] [nvarchar](max) NULL,
	[ShippingCarrierServiceGroupId] [nvarchar](max) NULL,
	[ContactPersonId] [nvarchar](max) NULL,
	[DefaultReceivingWarehouseId] [nvarchar](max) NULL,
	[EUSalesListCode] [nvarchar](max) NULL,
	[ImportDeclarationNumber] [nvarchar](max) NULL,
	[PurchaseOrderStatus] [nvarchar](max) NULL,
	[PaymentTermsName] [nvarchar](max) NULL,
	[DeliveryAddressLongitude] [float] NULL,
	[DocumentApprovalStatus] [nvarchar](max) NULL,
	[InvoiceAddressZipCode] [nvarchar](max) NULL,
	[ShippingCarrierServiceId] [nvarchar](max) NULL,
	[DefaultLedgerDimensionDisplayValue] [nvarchar](max) NULL,
	[DeliveryAddressTimeZone] [nvarchar](max) NULL,
	[AttentionInformation] [nvarchar](max) NULL,
	[DeliveryAddressStateId] [nvarchar](max) NULL,
	[DeliveryBuildingCompliment] [nvarchar](max) NULL,
	[IntrastatTransportModeCode] [nvarchar](max) NULL,
	[DeliveryAddressPostBox] [nvarchar](max) NULL,
	[IsOneTimeVendor] [nvarchar](max) NULL,
	[IntrastatPortId] [nvarchar](max) NULL,
	[OrdererPersonnelNumber] [nvarchar](max) NULL,
	[VendorPaymentMethodName] [nvarchar](max) NULL,
	[InvoiceAddressState] [nvarchar](max) NULL,
	[DefaultReceivingSiteId] [nvarchar](max) NULL,
	[LineDiscountVendorGroupCode] [nvarchar](max) NULL,
	[TransportationRoutePlanId] [nvarchar](max) NULL,
	[ZakatContractNumber] [nvarchar](max) NULL,
	[FormattedDeliveryAddress] [nvarchar](max) NULL,
	[TotalDiscountVendorGroupCode] [nvarchar](max) NULL,
	[TradeEndCustomerAccount] [nvarchar](max) NULL,
	[FiscalDocumentOperationTypeId] [nvarchar](max) NULL,
	[FinTagDisplayValue] [nvarchar](max) NULL
) ON [PRIMARY] TEXTIMAGE_ON [PRIMARY]
GO
/****** Object:  View [dbo].[vw_LPO_Master_export_to_253]    Script Date: 30/07/2025 12:27:44 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO












create view [dbo].[vw_LPO_Master_export_to_253]
as
SELECT [PurchaseOrderNumber]
    ,[OrderVendorAccountNumber]
	 ,[AccountingDate]
	  ,''[ContactName]
      ,''[Mobile]
      ,''[Notes]
	  ,'Sajid' [UserName]
	  ,'Created' [LPO_status]
	  ,(SELECT VendorOrganizationName
   
  FROM [MarinaDynamics365].[dbo].[VendorsV2] v
  where v.[VendorAccountNumber]=l.[OrderVendorAccountNumber]) AgentName
		 ,'D365' [sessionid]	
		 ,'' [Remarks]
		 ,(SELECT top 1
        [AgentEmail]   FROM [MarinaDashboard].[dbo].[LPO_Agent_Email_Mx] e
	  where e.Manf_id=l.OrderVendorAccountNumber)Email
		 ,(SELECT top 1
        CCEmail  FROM [MarinaDashboard].[dbo].[LPO_Agent_Email_Mx] e
	  where e.Manf_id=l.OrderVendorAccountNumber) CCEmail
			
	    ,'' [Order_id]
      ,'' [Last_Update_ff]
      ,getdate() [Last_Updated]
      ,'' [Last_Update_mgt]
      ,getdate()  [Last_Updated_date_mgt]
      ,'' [Last_Update_mgt_user]
      ,'' [Lacking_Status]
      ,'' [Order_id_txt]
      ,'Normal' [Creation_Type]
	  ,'' [Parent_LPO]
      ,'' [Child_LPO]
      ,'' [LPONotes]
	  ,[DeliveryAddressDescription]
	 ,case when [DefaultReceivingWarehouseId]='WH0002' then 8 else 1 end [Store2]
      
--	  ,(SELECT
  --    [Store2]
 ---- FROM [MarinaDynamics365].[dbo].[vw_LPO_WH_Agents] a
 -- where a.[Manf_Id]=l.OrderVendorAccountNumber)  [Store2]
	  ,'Yes' [LPO2022]
	   ,'' [Lacking_Remarks]
      ,''[Invoice_Dates]
      ,'1900-01-01 12:00:00'[Archived_Date]
      ,'' [Archived_by]
       ,[DeliveryAddressStreet] [Delivery_Place]
	
	   ,(SELECT  
      LocationNAme
  FROM [MarinaDynamics365].[dbo].[Mx_StoreCode] s
  where s.STORENAME=l.[DeliveryAddressDescription]) [Branch_delivery]
   ,(SELECT  
      LocationID
  FROM [MarinaDynamics365].[dbo].[Mx_StoreCode] s
  where s.STORENAME=l.[DeliveryAddressDescription])  LocationID

  ,''[LPO_Branch_Status]
      ,''[file_pdf]
      ,''[TRN_No]
      ,''[StockTransferred]
,[DeliveryAddressCountryRegionId]
,[DeliveryAddressCity]
,[DefaultReceivingWarehouseId]
   
  ,(select [AddressStreet]   FROM [MarinaDynamics365].[dbo].[VendorsV2] v 
  where v.[VendorAccountNumber]=l.[OrderVendorAccountNumber] ) VEndorAddressStreet

   ,(select [FormattedPrimaryAddress]   FROM [MarinaDynamics365].[dbo].[VendorsV2] v 
  where v.[VendorAccountNumber]=l.[OrderVendorAccountNumber] ) [FormattedPrimaryAddress]
  ,DocumentApprovalStatus
  ,PurchaseOrderStatus
    
  FROM [MarinaDynamics365].[dbo].[PurchaseOrderHeadersV2] l
  where AccountingDate>='2025-01-01'
GO
/****** Object:  View [dbo].[vw_ON_hand_Stock3_dummy]    Script Date: 30/07/2025 12:27:44 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO



/****** Script for SelectTopNRows command from SSMS  ******/
create view [dbo].[vw_ON_hand_Stock3_dummy]
as
SELECT [Item number]
      
      ,[Site]
	  ,[Site]+[Item number] ref
 
 
      ,[Available physical]
	  ,[Available physical] -isnull((SELECT
      sum([Sales qty])
     
  FROM [MarinaDynamics365].[dbo].[Stock_Batch_correction_final_v2] c
  where Remarks='Batch Corrected' and c.[Item number]=s.[Item number] and c.[Site]=s.[Site] ),0) Dummy

  FROM [MarinaDynamics365].[dbo].[ON hand Stock3] s
 -- where [Item number]='100250' and Site='AUH0001'
GO
/****** Object:  View [dbo].[vw_Mx_Item_Price_Hotel]    Script Date: 30/07/2025 12:27:44 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO

CREATE VIEW [dbo].[vw_Mx_Item_Price_Hotel]
AS
SELECT        dbo.Mx_Product_Master.[Item number], dbo.Mx_Product_Master.[Product name], dbo.Mx_Product_Master.DrugName, dbo.Mx_Product_Master.Drug_ID, dbo.PriceMaster_UploadRaw.[Amount in transaction currency]
FROM            dbo.Mx_Product_Master INNER JOIN
                         dbo.PriceMaster_UploadRaw ON dbo.Mx_Product_Master.[Item number] = dbo.PriceMaster_UploadRaw.Item
WHERE        (dbo.PriceMaster_UploadRaw.[Account selection] = 'UAE-HTL')
GO
/****** Object:  Table [dbo].[D365_Sales_Registers]    Script Date: 30/07/2025 12:27:44 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[D365_Sales_Registers](
	[ShippingWarehouseId] [varchar](250) NULL,
	[STORENAME] [varchar](50) NULL,
	[RequestedReceiptDate] [date] NULL,
	[ItemNumber] [varchar](250) NULL,
	[ProductName] [nvarchar](max) NULL,
	[PurchaseUnitSymbol] [nvarchar](max) NULL,
	[BOMUnitSymbol] [nvarchar](max) NULL,
	[SalesSalesTaxItemGroupCode] [nvarchar](max) NULL,
	[Drug_id] [varchar](50) NULL,
	[ProductGroupId] [nvarchar](max) NULL,
	[RetailProductCategoryname] [nvarchar](max) NULL,
	[SalesUnitSymbol] [varchar](250) NULL,
	[OrderedSalesQuantity] [float] NULL,
	[Factor] [int] NULL,
	[Qty_Sold] [float] NULL,
	[LocationID] [varchar](50) NULL,
	[ShortName] [varchar](50) NULL
) ON [PRIMARY] TEXTIMAGE_ON [PRIMARY]
GO
/****** Object:  View [dbo].[D365_vw_Sales_CheckSum_By_Date]    Script Date: 30/07/2025 12:27:44 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO


create view [dbo].[D365_vw_Sales_CheckSum_By_Date]
as
SELECT 
      [RequestedReceiptDate]
      ,count([ItemNumber]) ItemCount
     
  FROM [MarinaDynamics365].[dbo].[D365_Sales_Registers]
  group by [RequestedReceiptDate]
GO
/****** Object:  View [dbo].[vw_TransferOrder_Pending_Sum_BR2WH]    Script Date: 30/07/2025 12:27:44 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE VIEW [dbo].[vw_TransferOrder_Pending_Sum_BR2WH]
AS
SELECT        dbo.TransferOrderHeaders.ReceivingWarehouseId, dbo.TransferOrderLines.ItemNumber, SUM(dbo.TransferOrderLines.TransferQuantity) AS Pending_Qty, dbo.TransferOrderHeaders.ShippingWarehouseId
FROM            dbo.TransferOrderHeaders LEFT OUTER JOIN
                         dbo.TransferOrderLines ON dbo.TransferOrderHeaders.TransferOrderNumber = dbo.TransferOrderLines.TransferOrderNumber
WHERE        (dbo.TransferOrderHeaders.ShippingWarehouseId NOT IN (N'WH0001', N'WH0002')) AND (dbo.TransferOrderHeaders.TransferOrderStatus IN (N'Shipped')) AND (dbo.TransferOrderHeaders.ReceivingWarehouseId IN (N'WH0001',
                          N'WH0002')) AND (dbo.TransferOrderLines.ItemNumber IS NOT NULL)
GROUP BY dbo.TransferOrderHeaders.ReceivingWarehouseId, dbo.TransferOrderLines.ItemNumber, dbo.TransferOrderHeaders.ShippingWarehouseId
GO
/****** Object:  Table [dbo].[FEB2024_REORDER_TO_D365]    Script Date: 30/07/2025 12:27:44 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[FEB2024_REORDER_TO_D365](
	[Item Number] [varchar](50) NULL,
	[Product Name] [varchar](254) NULL
) ON [PRIMARY]
GO
/****** Object:  View [dbo].[vw_JUNE_ALL_RE_ORDER_CONCAT_RAW]    Script Date: 30/07/2025 12:27:44 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE VIEW [dbo].[vw_JUNE_ALL_RE_ORDER_CONCAT_RAW] AS Select [Item Number],[Product Name] ,isnull([800 CENT],0) QTY ,53 locationid FROM [MarinaDynamics365].[dbo].[FEB2024_REORDER_TO_D365] union Select [Item Number],[Product Name] ,isnull([800 DHCC],0) QTY ,53 locationid FROM [MarinaDynamics365].[dbo].[FEB2024_REORDER_TO_D365] union Select [Item Number],[Product Name] ,isnull([800 PARK],0) QTY ,53 locationid FROM [MarinaDynamics365].[dbo].[FEB2024_REORDER_TO_D365] union Select [Item Number],[Product Name] ,isnull([800 PH],0) QTY ,53 locationid FROM [MarinaDynamics365].[dbo].[FEB2024_REORDER_TO_D365] union Select [Item Number],[Product Name] ,isnull([800 SHJ],0) QTY ,53 locationid FROM [MarinaDynamics365].[dbo].[FEB2024_REORDER_TO_D365] union Select [Item Number],[Product Name] ,isnull([800ALAIN],0) QTY ,53 locationid FROM [MarinaDynamics365].[dbo].[FEB2024_REORDER_TO_D365] union Select [Item Number],[Product Name] ,isnull([800ALQUZ],0) QTY ,53 locationid FROM [MarinaDynamics365].[dbo].[FEB2024_REORDER_TO_D365] union Select [Item Number],[Product Name] ,isnull([800ARJAN],0) QTY ,53 locationid FROM [MarinaDynamics365].[dbo].[FEB2024_REORDER_TO_D365] union Select [Item Number],[Product Name] ,isnull([800CAPTL],0) QTY ,53 locationid FROM [MarinaDynamics365].[dbo].[FEB2024_REORDER_TO_D365] union Select [Item Number],[Product Name] ,isnull([800CRCLE],0) QTY ,53 locationid FROM [MarinaDynamics365].[dbo].[FEB2024_REORDER_TO_D365] union Select [Item Number],[Product Name] ,isnull([800RAK],0) QTY ,53 locationid FROM [MarinaDynamics365].[dbo].[FEB2024_REORDER_TO_D365] union Select [Item Number],[Product Name] ,isnull([800SARAY],0) QTY ,53 locationid FROM [MarinaDynamics365].[dbo].[FEB2024_REORDER_TO_D365] union Select [Item Number],[Product Name] ,isnull([800STORE],0) QTY ,53 locationid FROM [MarinaDynamics365].[dbo].[FEB2024_REORDER_TO_D365] union Select [Item Number],[Product Name] ,isnull([800ZAHIA],0) QTY ,53 locationid FROM [MarinaDynamics365].[dbo].[FEB2024_REORDER_TO_D365]
GO
/****** Object:  View [dbo].[vw_TransferOrderLines_Pending_InBR2WH_Transit]    Script Date: 30/07/2025 12:27:44 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE VIEW [dbo].[vw_TransferOrderLines_Pending_InBR2WH_Transit]
AS
SELECT        dbo.TransferOrderLines.TransferOrderNumber, dbo.TransferOrderLines.LineNumber, dbo.TransferOrderLines.TransferQuantity, dbo.TransferOrderLines.LineStatus, dbo.TransferOrderLines.ShippingSiteId, 
                         dbo.TransferOrderLines.ItemNumber, dbo.TransferOrderLines.ShippingWarehouseId, dbo.TransferOrderLines.RequestedReceiptDate, dbo.TransferOrderLines.ShippedQuantity, dbo.TransferOrderLines.ReceivedQuantity, 
                         dbo.TransferOrderLines.ReceivingInventoryLotId, dbo.TransferOrderLines.ShippingInventoryLotId, dbo.TransferOrderLines.RemainingShippedQuantity, dbo.TransferOrderLines.RequestedShippingDate, 
                         dbo.TransferOrderLines.ReceivingTransitInventoryLotId, dbo.TransferOrderLines.ItemBatchNumber, dbo.TransferOrderHeaders.TransferOrderStatus, dbo.TransferOrderHeaders.ReceivingWarehouseId
FROM            dbo.TransferOrderLines RIGHT OUTER JOIN
                         dbo.TransferOrderHeaders ON dbo.TransferOrderLines.TransferOrderNumber = dbo.TransferOrderHeaders.TransferOrderNumber
WHERE        (dbo.TransferOrderHeaders.TransferOrderStatus IN ('Shipped')) AND (dbo.TransferOrderHeaders.ReceivingWarehouseId IN (N'WH0001', N'WH0002')) AND (NOT (dbo.TransferOrderLines.ShippingWarehouseId IN (N'WH0001', 
                         N'WH0002')))
GO
/****** Object:  Table [dbo].[CRM_FAILD_INVOICE_UPLOAD_RAW]    Script Date: 30/07/2025 12:27:44 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[CRM_FAILD_INVOICE_UPLOAD_RAW](
	[Integration log id] [varchar](50) NULL,
	[Order_id] [varchar](50) NULL,
	[Order_source] [varchar](50) NULL,
	[Branch_name] [varchar](50) NULL,
	[Branch_id] [varchar](50) NULL,
	[Agent_name] [varchar](50) NULL,
	[Status] [varchar](50) NULL,
	[With_insurance] [varchar](50) NULL,
	[Patient_name] [varchar](50) NULL,
	[Driver] [varchar](50) NULL,
	[Schedule_date] [varchar](50) NULL,
	[Payment_method] [varchar](50) NULL,
	[Reference_number] [varchar](50) NULL,
	[Sub_total] [varchar](50) NULL,
	[Delivery_charges] [varchar](50) NULL,
	[Discount] [varchar](50) NULL,
	[CRM total] [varchar](50) NULL,
	[Header status] [varchar](50) NULL,
	[Latest status] [varchar](50) NULL,
	[Header remarks] [varchar](max) NULL,
	[Sales order] [varchar](50) NULL,
	[parnter_name] [varchar](50) NULL,
	[additional_charges] [varchar](50) NULL,
	[Settled] [varchar](50) NULL,
	[Voucher] [varchar](50) NULL,
	[SKU] [varchar](50) NULL,
	[Name] [varchar](254) NULL,
	[Quantity] [varchar](50) NULL,
	[Price_without_vat] [varchar](50) NULL,
	[Vat_value] [varchar](50) NULL,
	[Price_with_vat] [varchar](50) NULL,
	[Line discount] [varchar](50) NULL,
	[Vat] [varchar](50) NULL,
	[Line number] [varchar](50) NULL,
	[Line status] [varchar](50) NULL,
	[Line remarks] [varchar](50) NULL,
	[Batch] [varchar](50) NULL,
	[Expiry] [varchar](50) NULL
) ON [PRIMARY] TEXTIMAGE_ON [PRIMARY]
GO
/****** Object:  View [dbo].[vw_Negtaive_sales_crm]    Script Date: 30/07/2025 12:27:44 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO



/****** Script for SelectTopNRows command from SSMS  ******/

create view [dbo].[vw_Negtaive_sales_crm]
as
SELECT 

  [Branch_id] [Store Code]
   ,[SKU] [Item number]
   ,[Name] [Item Name]
   ,[Branch_id] [Site]
   ,[Branch_id] [Warehouse]
   ,[Branch_id] [Location]
    ,[Batch] [Batch number]
	,'' [Expiry Date]
	,'' [Unit]
	,sum(cast([Quantity] as decimal(8,2))) [Sales qty1]
	,'' [Available qty]
	,sum(cast([Quantity] as decimal(8,2))) - CAST(
        REPLACE(
            REPLACE(
                REPLACE(0, CHAR(13) + CHAR(10), ''), -- Removes newline characters
            CHAR(13), ''), -- Removes line feed characters
        ',', '') -- Removes comma characters
    AS DECIMAL(18, 2))   [Sales qty]
	 , [Branch_id] +  [SKU]  ref
	 , ROW_NUMBER() OVER (PARTITION BY [Branch_id]+[SKU] ORDER BY (SELECT NULL))  Seq
	 ,(select count([Batch])from  [MarinaDynamics365].[dbo].[CRM_FAILD_INVOICE_UPLOAD_RAW] n
	 where n.[Branch_id]+n.[SKU]=n2.[Branch_id]+n2.[SKU]) Line_Count
	   ,[Order_id]
      ,[Branch_name]

  FROM [MarinaDynamics365].[dbo].[CRM_FAILD_INVOICE_UPLOAD_RAW] n2
   group by  [Branch_id]
   ,[SKU]
   ,[Name]
   ,[Branch_id]
   ,[Branch_id]
   ,[Branch_id]
    ,[Batch]
	  ,[Order_id]
      ,[Branch_name]
GO
/****** Object:  UserDefinedFunction [dbo].[RemoveSpecialChar]    Script Date: 30/07/2025 12:27:44 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO





CREATE FUNCTION [dbo].[RemoveSpecialChar] (@s VARCHAR(256)) 
RETURNS VARCHAR(256) 
WITH SCHEMABINDING
    BEGIN
        IF @s IS NULL
            RETURN NULL
        DECLARE @s2 VARCHAR(256) = '',
                @l INT = LEN(@s),
                @p INT = 1

        WHILE @p <= @l
            BEGIN
                DECLARE @c INT
                SET @c = ASCII(SUBSTRING(@s, @p, 1))
                IF @c BETWEEN 48 AND 57
                   OR  @c BETWEEN 65 AND 90
                   OR  @c BETWEEN 97 AND 122
                    SET @s2 = @s2 + CHAR(@c)
					else
					 SET @s2 =@s2 +' '
					
                SET @p = @p + 1
            END

        IF LEN(@s2) = 0
            RETURN NULL

        RETURN @s2
		end
GO
/****** Object:  View [dbo].[vw_FEB2024_MinMax_Order_Branch_Final]    Script Date: 30/07/2025 12:27:44 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO













create view [dbo].[vw_FEB2024_MinMax_Order_Branch_Final]
as

SELECT [ItemNumber]
      ,[ProductName]
      ,[ProductGroupId]
      ,[RetailProductCategoryname]
      ,[SalesSalesTaxItemGroupCode]
      ,[Drug_id]
      ,[STORECODE]
      ,[LocationID]
      ,[ShortName]
      ,cast(dbo.RemoveSpecialChar([Min]) as int) [Min]
      ,cast(dbo.RemoveSpecialChar([Max]) as int) [Max]
      ,[Cost]
      ,[Price]
      ,[Vendor]
      ,floor([Stock]) [Stock]
      ,[Pending_Stock]
	-- , [dbo].[CalCulateOrder]([ItemNumber],[LocationID],(floor([Stock])-floor(Unposted_Qty))+([Pending_Stock]-TR_Pending) ,[Min],[Max]) [Order]
--	, [dbo].[CalCulateOrder]([ItemNumber],[LocationID],floor([Stock])+([Pending_Stock]-TR_Pending) ,[Min],[Max]) [Order]
	, [dbo].[CalCulateOrder_order](floor([Stock])+([Pending_Stock]-TR_Pending) ,cast(dbo.RemoveSpecialChar([Min]) as int),cast(dbo.RemoveSpecialChar([Max]) as int)) [Order]
	  ,floor(CONS) CONS
	  ,TR_Pending
	  ,Unposted_Qty
	  ,order_group
  FROM [MarinaDynamics365].[dbo].[MX_Product_MinMax_Price_Vendor_Stock]
  where  CONS+cast(dbo.RemoveSpecialChar([Min]) as int)+cast(dbo.RemoveSpecialChar([Max]) as int)+[Stock]<>0
  and [STORECODE] not in ('WH0001','WH0002')
GO
/****** Object:  View [dbo].[vw_TranferJournet_template]    Script Date: 30/07/2025 12:27:44 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO






create view [dbo].[vw_TranferJournet_template]
as
SELECT 

	'' JOURNALNUMBER	
	, [Item number] ITEMNUMBER
	,  ROW_NUMBER() OVER(ORDER BY  [Item number] ASC) LINENUMBER 
	,(SELECT [DEFAULTLEDGERDIMENSIONDISPLAYVALUE]
			FROM [MarinaDynamics365].[dbo].[vw_Product_LEDGERDIMENSION] L 
			WHERE L.[ITEM NUMBER] =S.[ITEM NUMBER] 
			AND L.[STORECODE]=S.[Site]) DEFAULTLEDGERDIMENSIONDISPLAYVALUE
   ,S.[Store Code] DESTINATIONINVENTORYSITEID
   ,S.[Store Code] DESTINATIONWAREHOUSEID
   , [Old Batch number] DESTINATIONITEMBATCHNUMBER
   , 'Storage' DESTINATIONWAREHOUSELOCATIONID	
   ,CASE WHEN [Sales qty]<= isnull([New_Qty],0) THEN [Sales qty] ELSE isnull([New_Qty],0) end INVENTORYQUANTITY
   ,'ITRANS' JOURNALNAMEID	
   ,S.[Store Code] SOURCEINVENTORYSITEID
   ,S.[Store Code] SOURCEWAREHOUSEID
   , [New_Batch] SOURCEITEMBATCHNUMBER
   ,'Storage' SOURCEWAREHOUSELOCATIONID	
   ,FORMAT(GETDATE(), 'M/dd/yyyy 00:00')  TRANSACTIONDATE
  , '1.000000000000' UNITCOSTQUANTITY	
 FROM [MarinaDynamics365].[dbo].[Stock_Batch_correction_final_2nd_pass] S
	  where case when REMARKS='Batch Corrected' and [Old Batch number]=[New_Batch] then 'Matching' 
	    WHEN REMARKS in ('Batch Allocated and corrected','Batch Allocated and corrected more stocks') THEN 'Batch Corrected'
		else  REMARKS end='Batch Corrected'
		and [Old Batch number]<>[New_Batch]
GO
/****** Object:  View [dbo].[vw_TransferOrderLines_WH2BR_Received]    Script Date: 30/07/2025 12:27:44 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO

CREATE VIEW [dbo].[vw_TransferOrderLines_WH2BR_Received]
AS
SELECT        dbo.TransferOrderLines.TransferOrderNumber, dbo.TransferOrderLines.LineNumber, dbo.TransferOrderLines.TransferQuantity, dbo.TransferOrderLines.LineStatus, dbo.TransferOrderLines.ShippingSiteId, 
                         dbo.TransferOrderHeaders.ReceivingWarehouseId, dbo.TransferOrderLines.ItemNumber, dbo.TransferOrderLines.ShippingWarehouseId, dbo.TransferOrderLines.RequestedReceiptDate, 
                         dbo.TransferOrderLines.ShippedQuantity, dbo.TransferOrderLines.ReceivedQuantity, dbo.TransferOrderLines.ReceivingInventoryLotId, dbo.TransferOrderLines.ShippingInventoryLotId, 
                         dbo.TransferOrderLines.RemainingShippedQuantity, dbo.TransferOrderLines.RequestedShippingDate, dbo.TransferOrderLines.ReceivingTransitInventoryLotId, dbo.TransferOrderLines.ItemBatchNumber, 
                         dbo.TransferOrderHeaders.TransferOrderStatus, dbo.TransferOrderHeaders.ShippingWarehouseId AS Expr1, dbo.Mx_Product_Master_new.ProductName, dbo.Mx_Product_Master_new.ProductGroupId, 
                         CASE WHEN dbo.TransferOrderHeaders.[ShippingWarehouseId] = 'WH0001' THEN 1 WHEN dbo.TransferOrderHeaders.[ShippingWarehouseId] = 'WH0002' THEN 8 END AS WH
FROM            dbo.TransferOrderLines INNER JOIN
                         dbo.TransferOrderHeaders ON dbo.TransferOrderLines.TransferOrderNumber = dbo.TransferOrderHeaders.TransferOrderNumber INNER JOIN
                         dbo.Mx_Product_Master_new ON dbo.TransferOrderLines.ItemNumber = dbo.Mx_Product_Master_new.ItemNumber
WHERE        (dbo.TransferOrderHeaders.TransferOrderStatus = N'Received') AND (dbo.TransferOrderHeaders.ShippingWarehouseId IN (N'WH0001', N'WH0002')) AND (dbo.TransferOrderLines.ReceivedQuantity <> 0)
GO
/****** Object:  Table [dbo].[PurchaseOrderLinesV2]    Script Date: 30/07/2025 12:27:44 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[PurchaseOrderLinesV2](
	[dataAreaId] [nvarchar](max) NULL,
	[PurchaseOrderNumber] [nvarchar](max) NULL,
	[LineNumber] [bigint] NULL,
	[ProcurementProductCategoryName] [nvarchar](max) NULL,
	[Tax1099SAddressOrLegalDescription] [nvarchar](max) NULL,
	[FixedAssetNumber] [nvarchar](max) NULL,
	[Tax1099GTaxYear] [bigint] NULL,
	[VendorRetentionTermRuleDescription] [nvarchar](max) NULL,
	[ProjectSalesUnitSymbol] [nvarchar](max) NULL,
	[OrderedPurchaseQuantity] [float] NULL,
	[FormattedDelveryAddress] [nvarchar](max) NULL,
	[ProjectCategoryId] [nvarchar](max) NULL,
	[AccountingDistributionTemplateName] [nvarchar](max) NULL,
	[ItemNumber] [nvarchar](max) NULL,
	[DeliveryAddressDescription] [nvarchar](max) NULL,
	[MultilineDiscountPercentage] [float] NULL,
	[PurchaseRequisitionId] [nvarchar](max) NULL,
	[DeliveryCityInKana] [nvarchar](max) NULL,
	[RetailProductVariantNumber] [nvarchar](max) NULL,
	[DeliveryStreetInKana] [nvarchar](max) NULL,
	[LineDiscountAmount] [float] NULL,
	[ProductStyleId] [nvarchar](max) NULL,
	[IsTax1099SPropertyOrServices] [nvarchar](max) NULL,
	[ProjectTaxGroupCode] [nvarchar](max) NULL,
	[ProjectTaxItemGroupCode] [nvarchar](max) NULL,
	[Barcode] [nvarchar](max) NULL,
	[IsNewFixedAsset] [nvarchar](max) NULL,
	[ProductConfigurationId] [nvarchar](max) NULL,
	[Tax1099GVendorStateId] [nvarchar](max) NULL,
	[WorkflowState] [nvarchar](max) NULL,
	[IsIntrastatTriangularDeal] [nvarchar](max) NULL,
	[Tax1099StateId] [nvarchar](max) NULL,
	[IsPartialDeliveryPrevented] [nvarchar](max) NULL,
	[MultilineDiscountAmount] [float] NULL,
	[Tax1099Type] [nvarchar](max) NULL,
	[RequestedDeliveryDate] [datetime2](0) NULL,
	[ItemBatchNumber] [nvarchar](max) NULL,
	[DeliveryAddressCountryRegionId] [nvarchar](max) NULL,
	[DeliveryAddressLatitude] [float] NULL,
	[ReceivingWarehouseId] [nvarchar](max) NULL,
	[DeliveryAddressCity] [nvarchar](max) NULL,
	[ConfirmedDeliveryDate] [datetime2](0) NULL,
	[PurchaseUnitSymbol] [nvarchar](max) NULL,
	[PurchaseRebateVendorGroupId] [nvarchar](max) NULL,
	[IsDeleted] [nvarchar](max) NULL,
	[RequesterPersonnelNumber] [nvarchar](max) NULL,
	[ProjectId] [nvarchar](max) NULL,
	[IsTax1099GTradeOrBusinessIncome] [nvarchar](max) NULL,
	[ProjectLinePropertyId] [nvarchar](max) NULL,
	[DeliveryAddressDistrictName] [nvarchar](max) NULL,
	[DeliveryAddressCountyId] [nvarchar](max) NULL,
	[Tax1099SBuyerPartOfRealEstateTaxAmount] [float] NULL,
	[ProductSizeId] [nvarchar](max) NULL,
	[FixedPriceCharges] [float] NULL,
	[DeliveryAddressZipCode] [nvarchar](max) NULL,
	[UnitWeight] [float] NULL,
	[Tax1099SClosingDate] [datetime2](0) NULL,
	[DeliveryAddressDunsNumber] [nvarchar](max) NULL,
	[IsAddedByChannel] [nvarchar](max) NULL,
	[PurchasePriceQuantity] [float] NULL,
	[ServiceFiscalInformationCode] [nvarchar](max) NULL,
	[DeliveryAddressName] [nvarchar](max) NULL,
	[Tax1099BoxId] [nvarchar](max) NULL,
	[BudgetReservationLineNumber] [bigint] NULL,
	[BOMId] [nvarchar](max) NULL,
	[FixedAssetTransactionType] [nvarchar](max) NULL,
	[DeliveryAddressStreetNumber] [nvarchar](max) NULL,
	[ReceivingWarehouseLocationId] [nvarchar](max) NULL,
	[NGPCode] [bigint] NULL,
	[IsDeliveryAddressPrivate] [nvarchar](max) NULL,
	[OriginStateId] [nvarchar](max) NULL,
	[ItemWithholdingTaxGroupCode] [nvarchar](max) NULL,
	[MainAccountIdDisplayValue] [nvarchar](max) NULL,
	[OrderedInventoryStatusId] [nvarchar](max) NULL,
	[CatchWeightUnitSymbol] [nvarchar](max) NULL,
	[DeliveryAddressCountryRegionISOCode] [nvarchar](max) NULL,
	[ItemSerialNumber] [nvarchar](max) NULL,
	[CalculateLineAmount] [nvarchar](max) NULL,
	[ReceivingSiteId] [nvarchar](max) NULL,
	[ProjectSalesCurrencyCode] [nvarchar](max) NULL,
	[IntrastatTransactionCode] [nvarchar](max) NULL,
	[DeliveryAddressLocationId] [nvarchar](max) NULL,
	[ProjectActivityNumber] [nvarchar](max) NULL,
	[SalesTaxItemGroupCode] [nvarchar](max) NULL,
	[RouteId] [nvarchar](max) NULL,
	[ProductVersionId] [nvarchar](max) NULL,
	[ShipCalendarId] [nvarchar](max) NULL,
	[Tax1099GStateTaxWithheldAmount] [float] NULL,
	[IntrastatStatisticsProcedureCode] [nvarchar](max) NULL,
	[OverrideSalesTax] [nvarchar](max) NULL,
	[LineDescription] [nvarchar](max) NULL,
	[GSTHSTTaxType] [nvarchar](max) NULL,
	[DeliveryAddressStreet] [nvarchar](max) NULL,
	[ConfirmedShippingDate] [datetime2](0) NULL,
	[CustomerReference] [nvarchar](max) NULL,
	[InventoryLotId] [nvarchar](max) NULL,
	[VendorRetentionTermRuleId] [nvarchar](max) NULL,
	[SalesTaxGroupCode] [nvarchar](max) NULL,
	[IsDeliveryAddressOrderSpecific] [nvarchar](max) NULL,
	[CustomerRequisitionNumber] [nvarchar](max) NULL,
	[PurchasePrice] [float] NULL,
	[PlanningPriority] [float] NULL,
	[WillProductReceivingCrossDockProducts] [nvarchar](max) NULL,
	[LineDiscountPercentage] [float] NULL,
	[DIOTOperationType] [nvarchar](max) NULL,
	[FixedAssetValueModelId] [nvarchar](max) NULL,
	[OrderedCatchWeightQuantity] [float] NULL,
	[ProjectWorkerPersonnelNumber] [nvarchar](max) NULL,
	[AllowedUnderdeliveryPercentage] [float] NULL,
	[AllowedOverdeliveryPercentage] [float] NULL,
	[DeliveryAddressLongitude] [float] NULL,
	[FixedAssetGroupId] [nvarchar](max) NULL,
	[PurchaseOrderLineStatus] [nvarchar](max) NULL,
	[IntrastatCommodityCode] [nvarchar](max) NULL,
	[DefaultLedgerDimensionDisplayValue] [nvarchar](max) NULL,
	[DeliveryAddressTimeZone] [nvarchar](max) NULL,
	[BudgetReservationDocumentNumber] [nvarchar](max) NULL,
	[ProductColorId] [nvarchar](max) NULL,
	[CFOPCode] [nvarchar](max) NULL,
	[DeliveryAddressStateId] [nvarchar](max) NULL,
	[DeliveryBuildingCompliment] [nvarchar](max) NULL,
	[IntrastatTransportModeCode] [nvarchar](max) NULL,
	[Tax1099StateAmount] [float] NULL,
	[DeliveryAddressPostBox] [nvarchar](max) NULL,
	[LineAmount] [float] NULL,
	[OriginCountryRegionId] [nvarchar](max) NULL,
	[IntrastatPortId] [nvarchar](max) NULL,
	[IntrastatSpecialMovementCode] [nvarchar](max) NULL,
	[Tax1099Amount] [float] NULL,
	[BarCodeSetupId] [nvarchar](max) NULL,
	[VendorInvoiceMatchingPolicy] [nvarchar](max) NULL,
	[Tax1099GVendorStateTaxId] [nvarchar](max) NULL,
	[ProjectSalesPrice] [float] NULL,
	[RequestedShippingDate] [datetime2](0) NULL,
	[PurchaseOrderLineCreationMethod] [nvarchar](max) NULL,
	[WithholdingTaxGroupCode] [nvarchar](max) NULL,
	[SkipCreateAutoCharges] [nvarchar](max) NULL,
	[ExternalItemNumber] [nvarchar](max) NULL,
	[IsProjectPayWhenPaid] [nvarchar](max) NULL,
	[IsLineStopped] [nvarchar](max) NULL,
	[IntrastatStatisticValue] [float] NULL,
	[DlvMode] [nvarchar](max) NULL,
	[DlvTerm] [nvarchar](max) NULL,
	[HSFOC] [nvarchar](max) NULL,
	[FinTagDisplayValue] [nvarchar](max) NULL
) ON [PRIMARY] TEXTIMAGE_ON [PRIMARY]
GO
/****** Object:  Table [dbo].[ProductReceiptLines]    Script Date: 30/07/2025 12:27:44 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[ProductReceiptLines](
	[dataAreaId] [nvarchar](max) NULL,
	[RecordId] [bigint] NULL,
	[ProductStyleId] [nvarchar](max) NULL,
	[RemainingPurchaseQuantity] [float] NULL,
	[DeliveryAddressCountyId] [nvarchar](max) NULL,
	[ReceivingSiteId] [nvarchar](max) NULL,
	[ReceivedPurchaseQuantity] [float] NULL,
	[ExpectedDeliveryDate] [datetime2](0) NULL,
	[LineNumber] [float] NULL,
	[LineDescription] [nvarchar](max) NULL,
	[ItemNumber] [nvarchar](max) NULL,
	[PurchaseOrderNumber] [nvarchar](max) NULL,
	[ProductSizeId] [nvarchar](max) NULL,
	[RemainingInventoryQuantity] [float] NULL,
	[ReceivingWarehouseLocationId] [nvarchar](max) NULL,
	[ReceivedInventoryQuantity] [float] NULL,
	[PurchaseOrderLineNumber] [bigint] NULL,
	[ProductReceiptHeaderRecordId] [bigint] NULL,
	[ItemSerialNumber] [nvarchar](max) NULL,
	[ProductConfigurationId] [nvarchar](max) NULL,
	[DeliveryAddressCountryRegionId] [nvarchar](max) NULL,
	[PurchaseUnitSymbol] [nvarchar](max) NULL,
	[OrderedPurchaseQuantity] [float] NULL,
	[ProductNumber] [nvarchar](max) NULL,
	[ProductVersionId] [nvarchar](max) NULL,
	[ProductReceiptNumber] [nvarchar](max) NULL,
	[ProcurementProductCategoryHierarchyName] [nvarchar](max) NULL,
	[ExternalItemNumber] [nvarchar](max) NULL,
	[ReceivedInventoryStatusId] [nvarchar](max) NULL,
	[ItemBatchNumber] [nvarchar](max) NULL,
	[ProductColorId] [nvarchar](max) NULL,
	[DeliveryAddressStateId] [nvarchar](max) NULL,
	[PurchaserPersonnelNumber] [nvarchar](max) NULL,
	[ProcurementProductCategoryName] [nvarchar](max) NULL,
	[ReceivingWarehouseId] [nvarchar](max) NULL,
	[ProductReceiptDate] [datetime2](0) NULL
) ON [PRIMARY] TEXTIMAGE_ON [PRIMARY]
GO
/****** Object:  View [dbo].[vw_PurchaseOrder_Status]    Script Date: 30/07/2025 12:27:44 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO

CREATE VIEW [dbo].[vw_PurchaseOrder_Status]
AS
SELECT        dbo.PurchaseOrderLinesV2.PurchaseOrderNumber, dbo.PurchaseOrderLinesV2.ReceivingWarehouseId, dbo.PurchaseOrderLinesV2.LineNumber, dbo.PurchaseOrderLinesV2.ItemNumber, 
                         dbo.PurchaseOrderLinesV2.LineDescription, dbo.PurchaseOrderLinesV2.OrderedPurchaseQuantity, ISNULL(dbo.ProductReceiptLines.ReceivedPurchaseQuantity, 0) AS Received, 
                         ISNULL(dbo.ProductReceiptLines.RemainingPurchaseQuantity, 0) AS Remaining, dbo.PurchaseOrderLinesV2.PurchaseOrderLineStatus, dbo.PurchaseOrderHeadersV2.PurchaseOrderStatus, 
                         CASE WHEN [PurchaseOrderLineStatus] = 'Canceled' THEN 'Canceled' WHEN [PurchaseOrderLineStatus] IN ('Invoiced', 'Received') AND ISNULL(dbo.ProductReceiptLines.RemainingPurchaseQuantity, 0) 
                         = 0 THEN 'Received Full' WHEN [PurchaseOrderLineStatus] IN ('Invoiced', 'Received', 'Backorder') AND RemainingPurchaseQuantity <> 0 THEN 'Received Partial' WHEN [PurchaseOrderLineStatus] IN ('Backorder') AND 
                         ISNULL(dbo.ProductReceiptLines.RemainingPurchaseQuantity, 0) = 0 AND
                             (SELECT        COUNT(PurchaseOrderNumber)
                               FROM            dbo.PurchaseOrderLinesV2 v2
                               WHERE        PurchaseOrderLineStatus IN ('Received', 'Invoiced') AND v2.PurchaseOrderNumber = dbo.PurchaseOrderLinesV2.PurchaseOrderNumber) = 0 THEN 'Pending' WHEN [PurchaseOrderLineStatus] IN ('Backorder') AND
                          ISNULL(dbo.ProductReceiptLines.RemainingPurchaseQuantity, 0) = 0 AND
                             (SELECT        COUNT(PurchaseOrderNumber)
                               FROM            dbo.PurchaseOrderLinesV2 v2
                               WHERE        PurchaseOrderLineStatus IN ('Received', 'Invoiced') AND v2.PurchaseOrderNumber = dbo.PurchaseOrderLinesV2.PurchaseOrderNumber) <> 0 THEN 'Lacking' ELSE CASE WHEN ISNULL(CONVERT(varchar, 
                         dbo.ProductReceiptLines.ReceivedPurchaseQuantity), 'x') = 'x' THEN 'Not found' ELSE 'Found' END END AS Remarks, dbo.PurchaseOrderHeadersV2.DocumentApprovalStatus, 
                         dbo.PurchaseOrderHeadersV2.RequestedDeliveryDate
FROM            dbo.PurchaseOrderLinesV2 INNER JOIN
                         dbo.PurchaseOrderHeadersV2 ON dbo.PurchaseOrderLinesV2.PurchaseOrderNumber = dbo.PurchaseOrderHeadersV2.PurchaseOrderNumber LEFT OUTER JOIN
                         dbo.ProductReceiptLines ON dbo.PurchaseOrderLinesV2.LineNumber = dbo.ProductReceiptLines.PurchaseOrderLineNumber AND 
                         dbo.PurchaseOrderLinesV2.ReceivingWarehouseId = dbo.ProductReceiptLines.ReceivingSiteId AND dbo.PurchaseOrderLinesV2.PurchaseOrderNumber = dbo.ProductReceiptLines.PurchaseOrderNumber AND 
                         dbo.PurchaseOrderLinesV2.ItemNumber = dbo.ProductReceiptLines.ItemNumber
WHERE        (dbo.PurchaseOrderLinesV2.ReceivingWarehouseId IN (N'WH0001', N'WH0002', N'WH0004'))
GO
/****** Object:  Table [dbo].[TransferOrderLines_WH2BR_Received]    Script Date: 30/07/2025 12:27:44 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[TransferOrderLines_WH2BR_Received](
	[TransferOrderNumber] [nvarchar](max) NULL,
	[LineNumber] [float] NULL,
	[TransferQuantity] [float] NULL,
	[LineStatus] [nvarchar](max) NULL,
	[ShippingSiteId] [nvarchar](max) NULL,
	[ReceivingWarehouseId] [nvarchar](max) NULL,
	[ItemNumber] [nvarchar](max) NULL,
	[ShippingWarehouseId] [nvarchar](max) NULL,
	[RequestedReceiptDate] [datetime2](0) NULL,
	[ShippedQuantity] [float] NULL,
	[ReceivedQuantity] [float] NULL,
	[ReceivingInventoryLotId] [nvarchar](max) NULL,
	[ShippingInventoryLotId] [nvarchar](max) NULL,
	[RemainingShippedQuantity] [float] NULL,
	[RequestedShippingDate] [datetime2](0) NULL,
	[ReceivingTransitInventoryLotId] [nvarchar](max) NULL,
	[ItemBatchNumber] [nvarchar](max) NULL,
	[TransferOrderStatus] [nvarchar](max) NULL,
	[Expr1] [nvarchar](max) NULL,
	[ProductName] [nvarchar](max) NULL,
	[ProductGroupId] [nvarchar](max) NULL,
	[WH] [int] NULL
) ON [PRIMARY] TEXTIMAGE_ON [PRIMARY]
GO
/****** Object:  View [dbo].[vw_TransferOrders_Latest_Received]    Script Date: 30/07/2025 12:27:44 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO


CREATE VIEW [dbo].[vw_TransferOrders_Latest_Received]
AS

WITH LatestReceives AS (
    SELECT 
        [ShippingSiteId],
        [ReceivingWarehouseId],
        [ItemNumber],
        [RequestedShippingDate],
        [RequestedReceiptDate],
        [ShippedQuantity],
        [ReceivedQuantity],
        [ItemBatchNumber],
        [WH],
        ROW_NUMBER() OVER (
            PARTITION BY ItemNumber, ReceivingWarehouseId 
            ORDER BY RequestedReceiptDate DESC
        ) AS RowNum
    FROM 
        MarinaDynamics365.[dbo].[TransferOrderLines_WH2BR_Received]
)
SELECT
    [ShippingSiteId],
    [ReceivingWarehouseId],
    [ItemNumber],
    [RequestedShippingDate],
    [RequestedReceiptDate],
    [ShippedQuantity],
    [ReceivedQuantity],
    [ItemBatchNumber],
    [WH]
FROM 
    LatestReceives
WHERE 
    RowNum = 1;
GO
/****** Object:  View [dbo].[vw_MX_Product_MinMax_Price_Vendor_Stock]    Script Date: 30/07/2025 12:27:44 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE VIEW [dbo].[vw_MX_Product_MinMax_Price_Vendor_Stock]
AS
SELECT        dbo.Mx_Product_Master_new_w_location.ItemNumber, dbo.Mx_Product_Master_new_w_location.ProductName, dbo.Mx_Product_Master_new_w_location.ProductGroupId, 
                         dbo.Mx_Product_Master_new_w_location.RetailProductCategoryname, dbo.Mx_Product_Master_new_w_location.SalesSalesTaxItemGroupCode, dbo.Mx_Product_Master_new_w_location.Drug_id, 
                         dbo.Mx_Product_Master_new_w_location.STORECODE, dbo.Mx_Product_Master_new_w_location.LocationID, dbo.Mx_Product_Master_new_w_location.ShortName, ISNULL(dbo.Mx_Min_Max_Raw_Upload.Min, '0') AS Min, 
                         ISNULL(dbo.Mx_Min_Max_Raw_Upload.Max, '0') AS Max, dbo.MX_Product_Cost_SPrice_Upload_Raw.Price2 AS Cost, dbo.MX_Product_Cost_SPrice_Upload_Raw.Price, dbo.MX_Product_Cost_SPrice_Upload_Raw.Vendor, 
                         ISNULL(dbo.Drug_Batch_Stock_ordered_SUM.Stock, 0) AS Stock, ISNULL(dbo.Drug_Batch_Stock_ordered_SUM.Ordered, 0) AS Pending_Stock, ISNULL(dbo.SALES_ZERO_STOCK_REF_COMBINED_60days.Qty_Sold, 0) AS CONS,
                          ISNULL(dbo.vw_TransferOrder_Pending_Sum_BR2WH.Pending_Qty, 0) AS TR_Pending, dbo.Unposted_Sales_Invoice.Qty AS Unposted_Qty, dbo.Mx_Product_Master_new_w_location.Order_Group
FROM            dbo.Mx_Product_Master_new_w_location LEFT OUTER JOIN
                         dbo.MX_Product_Cost_SPrice_Upload_Raw ON dbo.Mx_Product_Master_new_w_location.ItemNumber = dbo.MX_Product_Cost_SPrice_Upload_Raw.[Item number] LEFT OUTER JOIN
                         dbo.Unposted_Sales_Invoice ON dbo.Mx_Product_Master_new_w_location.ItemNumber = dbo.Unposted_Sales_Invoice.ItemNumber AND 
                         dbo.Mx_Product_Master_new_w_location.STORECODE = dbo.Unposted_Sales_Invoice.SiteCode LEFT OUTER JOIN
                         dbo.vw_TransferOrder_Pending_Sum_BR2WH ON dbo.Mx_Product_Master_new_w_location.STORECODE = dbo.vw_TransferOrder_Pending_Sum_BR2WH.ShippingWarehouseId AND 
                         dbo.Mx_Product_Master_new_w_location.ItemNumber = dbo.vw_TransferOrder_Pending_Sum_BR2WH.ItemNumber LEFT OUTER JOIN
                         dbo.SALES_ZERO_STOCK_REF_COMBINED_60days ON dbo.Mx_Product_Master_new_w_location.ItemNumber = dbo.SALES_ZERO_STOCK_REF_COMBINED_60days.ItemNumber AND 
                         dbo.Mx_Product_Master_new_w_location.LocationID = dbo.SALES_ZERO_STOCK_REF_COMBINED_60days.LocationID LEFT OUTER JOIN
                         dbo.Drug_Batch_Stock_ordered_SUM ON dbo.Mx_Product_Master_new_w_location.ItemNumber = dbo.Drug_Batch_Stock_ordered_SUM.ItemNumber AND 
                         dbo.Mx_Product_Master_new_w_location.STORECODE = dbo.Drug_Batch_Stock_ordered_SUM.SiteID LEFT OUTER JOIN
                         dbo.Mx_Min_Max_Raw_Upload ON dbo.Mx_Product_Master_new_w_location.ItemNumber = dbo.Mx_Min_Max_Raw_Upload.ItemNumber AND 
                         dbo.Mx_Product_Master_new_w_location.STORECODE = dbo.Mx_Min_Max_Raw_Upload.SiteCode
GO
/****** Object:  View [dbo].[vw_Sales_Registers+]    Script Date: 30/07/2025 12:27:44 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE VIEW [dbo].[vw_Sales_Registers+]
AS
SELECT        dbo.D365_Sales_Registers_from_PBi.RequestedReceiptDate, dbo.D365_Sales_Registers_from_PBi.ReceiptNumber, dbo.D365_Sales_Registers_from_PBi.[Location Id], dbo.D365_Sales_Registers_from_PBi.[Salesman Id], 
                         dbo.D365_Sales_Registers_from_PBi.[Line Number], dbo.D365_Sales_Registers_from_PBi.[Product Id], dbo.D365_Sales_Registers_from_PBi.LineDescription, dbo.D365_Sales_Registers_from_PBi.Unit, 
                         dbo.D365_Sales_Registers_from_PBi.[Qty Sold], dbo.D365_Sales_Registers_from_PBi.Batch, dbo.D365_Sales_Registers_from_PBi.SalesPrice, dbo.D365_Sales_Registers_from_PBi.[Discount Amount], 
                         dbo.D365_Sales_Registers_from_PBi.[Line Amount], dbo.D365_Sales_Registers_from_PBi.[Contact No], dbo.D365_Sales_Registers_from_PBi.[Customer Group], dbo.D365_Sales_Registers_from_PBi.[Discount Name], 
                         dbo.D365_Sales_Registers_from_PBi.[Retail Qty Sold], dbo.D365_Sales_Registers_from_PBi.[Bill No], dbo.ProductCategoryAssignments.ProductCategoryName AS Category, 
                         ProductCategoryAssignments_1.ProductCategoryName AS Brand, dbo.Workers.NameAlias AS SalesmanName
FROM            dbo.D365_Sales_Registers_from_PBi LEFT OUTER JOIN
                         dbo.Workers ON dbo.D365_Sales_Registers_from_PBi.[Salesman Id] = dbo.Workers.PersonnelNumber LEFT OUTER JOIN
                         dbo.ProductCategoryAssignments AS ProductCategoryAssignments_1 ON dbo.D365_Sales_Registers_from_PBi.[Product Id] = ProductCategoryAssignments_1.ProductNumber LEFT OUTER JOIN
                         dbo.ProductCategoryAssignments ON dbo.D365_Sales_Registers_from_PBi.[Product Id] = dbo.ProductCategoryAssignments.ProductNumber
WHERE        (dbo.ProductCategoryAssignments.ProductCategoryHierarchyName = N'Marina_Old_Category') AND (ProductCategoryAssignments_1.ProductCategoryHierarchyName = N'Marina_Brand')
GO
/****** Object:  View [dbo].[vw_TransferOrderHeaders_Pending_WH]    Script Date: 30/07/2025 12:27:44 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO


create view [dbo].[vw_TransferOrderHeaders_Pending_WH]
AS

SELECT        dbo.TransferOrderHeaders.TransferOrderNumber, dbo.TransferOrderHeaders.RequestedReceiptDate, dbo.TransferOrderHeaders.ShippingWarehouseId, dbo.TransferOrderHeaders.ReceivingWarehouseId, 
                         dbo.TransferOrderHeaders.ShippingAddressName, dbo.TransferOrderHeaders.TransferOrderStatus, dbo.TransferOrderHeaders.ReceivingAddressName, dbo.TransferOrderHeaders.RequestedShippingDate, 
                         dbo.Mx_StoreCode.STORENAME AS from_WH, Mx_StoreCode_1.STORENAME AS to_WH, Mx_StoreCode_1.LocationID
						  ,case when [ShippingWarehouseId]='WH0001' then 1
	   when [ShippingWarehouseId]='WH0002' then 8 end WH
FROM            dbo.TransferOrderHeaders INNER JOIN
                         dbo.Mx_StoreCode ON dbo.TransferOrderHeaders.ShippingWarehouseId = dbo.Mx_StoreCode.STORECODE INNER JOIN
                         dbo.Mx_StoreCode AS Mx_StoreCode_1 ON dbo.TransferOrderHeaders.ReceivingWarehouseId = Mx_StoreCode_1.STORECODE
WHERE        (dbo.TransferOrderHeaders.TransferOrderStatus = N'Created') AND (dbo.TransferOrderHeaders.ShippingWarehouseId IN (N'WH0001', N'WH0002'))
GO
/****** Object:  Table [dbo].[LPO_800WHAgents]    Script Date: 30/07/2025 12:27:44 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[LPO_800WHAgents](
	[Manf_Id] [varchar](50) NULL,
	[AgentName] [varchar](254) NULL,
	[WH] [varchar](50) NULL
) ON [PRIMARY]
GO
/****** Object:  View [dbo].[vw_LPO_WH_Agents]    Script Date: 30/07/2025 12:27:44 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE VIEW [dbo].[vw_LPO_WH_Agents]
AS
SELECT        dbo.VendorsV2.VendorAccountNumber AS Manf_Id, dbo.VendorsV2.VendorOrganizationName AS AgentName, ISNULL(dbo.LPO_800WHAgents.WH, '1') AS Store2
FROM            dbo.VendorsV2 LEFT OUTER JOIN
                         dbo.LPO_800WHAgents ON dbo.VendorsV2.VendorAccountNumber = dbo.LPO_800WHAgents.Manf_Id
GO
/****** Object:  View [dbo].[vw_Stock_by_Location_PIVOT]    Script Date: 30/07/2025 12:27:44 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO


create view [dbo].[vw_Stock_by_Location_PIVOT]

AS

SELECT *
FROM (
    SELECT [Itemnumber][Item number],[Productname][Product name],[Drug_id] ,[Site2], [Stock]
    FROM [MarinaDynamics365].[dbo].[vw_Mx_Stocks_by_Location_v2]
) AS SourceTable
PIVOT (
    SUM([Stock])
    FOR [Site2] IN ([WH0001-STORE]	,[WH0002-800STORE]	,[AUH0001-800 CENT]	,[AUH0002-800CAPTL],[AUH0003-800ALAIN]	,[DXB0001-GREENS]	,[DXB0002-CARE]	,[DXB0003-JUMEIRAH]	,[DXB0004-ONECNTRL]	,[DXB0005-GLDMILE1]	,[DXB0006-GLDMILE2]	,[DXB0007-ATLANTIS]	,[DXB0008-ATLNTS 2]	,[DXB0009-CENTER]	,[DXB0010-KHAWANIJ]	,[DXB0011-AVENUE]	,[DXB0012-800 DHCC]	,[DXB0013-800 PARK]	,[DXB0014-800 PH]	,[DXB0015-OLDTOWN]	,[DXB0016-SOUTH1]	,[DXB0017-PALM]	,[DXB0018-CWALK1]	,[DXB0019-800CRCLE]	,[DXB0020-800ALQUZ]	,[DXB0021-PROMINAD]	,[DXB0022-CARE 5]	,[DXB0023-800SARAY]	,[DXB0024-ARJAN]	,[DXB0025-800ARJAN]	,[DXB0026-CARE 1]	,[DXB0027-N.SHEBA]	,[DXB0028-SHOROOQ]	,[DXB0029-DCCS]	,[DXB0030-CARE 2]	,[DXB0031-CARE 3]	,[DXB0032-BURJ]	,[RAK0001-800RAK]	,[SHJ0001-800 SHJ]	,[SHJ0002-800ZAHIA]


)
) AS PivotTable;

GO
/****** Object:  View [dbo].[vw_lastest_Sales_per_item_Branch]    Script Date: 30/07/2025 12:27:44 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO

create view [dbo].[vw_lastest_Sales_per_item_Branch]
as
WITH LatestSales AS (
    SELECT 
        [Bill_No],
        [ItemNumber],
        [Qty_Sold],
        [LocationID],
        [Billdate],
		drug_id,
        ROW_NUMBER() OVER (PARTITION BY [ItemNumber], [LocationID] ORDER BY [Billdate] DESC) AS RowNum
    FROM 
        [MarinaDynamics365].[dbo].[SALES_ZERO_STOCK_REF_COMBINED]
)
SELECT 
    [Bill_No],
    [ItemNumber],
    [Qty_Sold],
    [LocationID],
    [Billdate],
	drug_id
FROM 
    LatestSales
WHERE 
    RowNum = 1;

GO
/****** Object:  View [dbo].[Stock_by_Location_PIVOT]    Script Date: 30/07/2025 12:27:44 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO


create view [dbo].[Stock_by_Location_PIVOT]

AS

SELECT *
FROM (
    SELECT [Itemnumber][Item number],[Productname][Product name],[Drug_id] ,[Site2], [Stock]
    FROM [MarinaDynamics365].[dbo].[vw_Mx_Stocks_by_Location_v2]
) AS SourceTable
PIVOT (
    SUM([Stock])
    FOR [Site2] IN ([WH0001-STORE]	,[WH0002-800STORE]	,[AUH0001-800 CENT]	,[AUH0002-800CAPTL],[AUH0003-800ALAIN]	,[DXB0001-GREENS]	,[DXB0002-CARE]	,[DXB0003-JUMEIRAH]	,[DXB0004-ONECNTRL]	,[DXB0005-GLDMILE1]	,[DXB0006-GLDMILE2]	,[DXB0007-ATLANTIS]	,[DXB0008-ATLNTS 2]	,[DXB0009-CENTER]	,[DXB0010-KHAWANIJ]	,[DXB0011-AVENUE]	,[DXB0012-800 DHCC]	,[DXB0013-800 PARK]	,[DXB0014-800 PH]	,[DXB0015-OLDTOWN]	,[DXB0016-SOUTH1]	,[DXB0017-PALM]	,[DXB0018-CWALK1]	,[DXB0019-800CRCLE]	,[DXB0020-800ALQUZ]	,[DXB0021-PROMINAD]	,[DXB0022-CARE 5]	,[DXB0023-800SARAY]	,[DXB0024-ARJAN]	,[DXB0025-800ARJAN]	,[DXB0026-CARE 1]	,[DXB0027-N.SHEBA]	,[DXB0028-SHOROOQ]	,[DXB0029-DCCS]	,[DXB0030-CARE 2]	,[DXB0031-CARE 3]	,[DXB0032-BURJ]	,[RAK0001-800RAK]	,[SHJ0001-800 SHJ]	,[SHJ0002-800ZAHIA]


)
) AS PivotTable;

GO
/****** Object:  Table [dbo].[D365_EXPIRY_UPLOAD_CSV_for_ORDER]    Script Date: 30/07/2025 12:27:44 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[D365_EXPIRY_UPLOAD_CSV_for_ORDER](
	[Item number] [varchar](50) NULL,
	[Product name] [varchar](300) NULL,
	[Bonus Item] [varchar](50) NULL,
	[Warehouse] [varchar](50) NULL,
	[Batch number] [varchar](50) NULL,
	[Location] [varchar](50) NULL,
	[Warehouse Name] [varchar](50) NULL,
	[Primary Vendor] [varchar](50) NULL,
	[Vendor Name] [varchar](300) NULL,
	[Expiration date] [varchar](50) NULL,
	[Physical inventory] [varchar](50) NULL,
	[Physical reserved] [varchar](50) NULL,
	[Available physical] [varchar](50) NULL,
	[Ordered] [varchar](50) NULL,
	[Ordered reserved] [varchar](50) NULL,
	[Total available] [varchar](50) NULL
) ON [PRIMARY]
GO
/****** Object:  View [dbo].[vw_Drug_Batch_Stock_COMBINED_D365_Expiry_order]    Script Date: 30/07/2025 12:27:44 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO





create view [dbo].[vw_Drug_Batch_Stock_COMBINED_D365_Expiry_order]
as
SELECT  [Item number] +[Warehouse]+[Batch number] [BatchID]
      	 , [Item number] [Drug_id]
         ,[Batch number] [Batch_No]
	   ,[dbo].[DateConvertShort_Long]([Expiration date]) [ExpDate]
	   ,cast([Available physical] as float) Stock
	   ,(select locationid from MarinaDynamics365.dbo.Mx_StoreCode s
	   where s.STORECODE=e.[Warehouse]) LocationID
	  ,[Warehouse]
	  	, case when [dbo].[DateConvertShort_Long]([Expiration date]) between DATEADD(month, DATEDIFF(month, 0, GETDATE()), 0) and DATEADD(month, DATEDIFF(month, 0, GETDATE()+180), 0)
	then '6mos' else 'no' end Mos6_Expiry
      FROM [MarinaDynamics365].[dbo].D365_EXPIRY_UPLOAD_CSV_for_ORDER e
where [location]='Storage'
GO
/****** Object:  View [dbo].[vw_Negtaive_sales]    Script Date: 30/07/2025 12:27:44 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO





/****** Script for SelectTopNRows command from SSMS  ******/
CREATE   view [dbo].[vw_Negtaive_sales]
as

SELECT [Store Code]
      ,[Item number]
      ,[Item Name]
      ,[Site]
      ,[Warehouse]
      ,[Location]
      ,replace([Batch number],'-','') [Batch number]
      ,[Expiry Date]
      ,[Unit]
      ,sum(cast([Sales qty] as decimal(8,2))) [Sales qty1]
	  ,CAST(
        REPLACE(
            REPLACE(
                REPLACE([Available qty], CHAR(13) + CHAR(10), ''), -- Removes newline characters
            CHAR(13), ''), -- Removes line feed characters
        ',', '') -- Removes comma characters
    AS DECIMAL(18, 2)) [Available qty]
	,sum(cast([Sales qty] as decimal(8,2))) - CAST(
        REPLACE(
            REPLACE(
                REPLACE([Available qty], CHAR(13) + CHAR(10), ''), -- Removes newline characters
            CHAR(13), ''), -- Removes line feed characters
        ',', '') -- Removes comma characters
    AS DECIMAL(18, 2))  [Sales qty]
	  , [Store Code] +  [Item number]  ref
	 , ROW_NUMBER() OVER (PARTITION BY [Site]+[Item number] ORDER BY (SELECT NULL))  Seq
	 ,(select count([Batch number])from  [MarinaDynamics365].[dbo].[Negtaive sales] n
	 where n.[Site]+n.[Item number]=n2.[Site]+n2.[Item number]) Line_Count
  FROM [MarinaDynamics365].[dbo].[Negtaive sales] n2

  group by [Store Code]
      ,[Item number]
      ,[Item Name]
      ,[Site]
      ,[Warehouse]
      ,[Location]
      ,replace([Batch number],'-','')
      ,[Expiry Date]
      ,[Unit]
   
	  ,[Available qty]
GO
/****** Object:  View [dbo].[vw_Drug_Batch_Stock_ordered_SUM_STORE]    Script Date: 30/07/2025 12:27:44 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO

create view  [dbo].[vw_Drug_Batch_Stock_ordered_SUM_STORE]
as
SELECT [ItemNumber]
      ,[Drug_id]
      ,[Stock]
      ,[Ordered]
      ,[SiteID]
      ,[Locationid]
  FROM [MarinaDynamics365].[dbo].[vw_Drug_Batch_Stock_ordered_SUM]
  where Locationid=35
GO
/****** Object:  Table [dbo].[Drug_Batch_Stock_COMBINED_D365_Expiry_order]    Script Date: 30/07/2025 12:27:44 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[Drug_Batch_Stock_COMBINED_D365_Expiry_order](
	[BatchID] [varchar](150) NULL,
	[Drug_id] [varchar](50) NULL,
	[Batch_No] [varchar](50) NULL,
	[ExpDate] [datetime] NULL,
	[Stock] [float] NULL,
	[LocationID] [varchar](50) NULL,
	[Warehouse] [varchar](50) NULL,
	[Mos6_Expiry] [varchar](4) NOT NULL
) ON [PRIMARY]
GO
/****** Object:  View [dbo].[vw_Drug_Batch_Stock_COMBINED_D365_Expiry_order_sum_6mos]    Script Date: 30/07/2025 12:27:44 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO

create view [dbo].[vw_Drug_Batch_Stock_COMBINED_D365_Expiry_order_sum_6mos]
as

SELECT [Drug_id]
      
      ,sum([Stock]) Stock
    
  FROM [MarinaDynamics365].[dbo].[Drug_Batch_Stock_COMBINED_D365_Expiry_order]
  group by [Drug_id]
  having sum([Stock])<>0
GO
/****** Object:  View [dbo].[vw_FEB2024_MinMax_Order_Branch_Final_ALL_WH]    Script Date: 30/07/2025 12:27:44 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO















create view [dbo].[vw_FEB2024_MinMax_Order_Branch_Final_ALL_WH]
as

SELECT [ItemNumber]
      ,[ProductName]
      ,[ProductGroupId]
      ,[RetailProductCategoryname]
      ,[SalesSalesTaxItemGroupCode]
      ,[Drug_id]
      ,[STORECODE]
      ,[LocationID]
      ,[ShortName]
      ,cast([Min] as int) [Min]
      ,cast([Max] as int) [Max]
      ,[Cost]
      ,[Price]
      ,[Vendor]
      ,floor([Stock]) [Stock]
      ,[Pending_Stock]
	-- , [dbo].[CalCulateOrder]([ItemNumber],[LocationID],(floor([Stock])-floor(Unposted_Qty))+([Pending_Stock]-TR_Pending) ,[Min],[Max]) [Order]
	 -- , [dbo].[CalCulateOrder]([ItemNumber],[LocationID],floor([Stock])+([Pending_Stock]-TR_Pending) ,[Min],[Max]) [Order]
	  --  , [dbo].[CalCulateOrder_by_Max]([ItemNumber],[LocationID],floor([Stock])+([Pending_Stock]-TR_Pending) ,[Max]) [Order] 2507
		  , [dbo].[CalCulateOrder_by_Max]([ItemNumber],[LocationID],floor([Stock])+[Pending_Stock] ,[Max]) [Order]
	  ,floor(CONS) CONS
	  ,TR_Pending
	  ,Unposted_Qty
	  ,case when order_group='Not Classified' then 'Warehouse' else order_group end order_group
  FROM [MarinaDynamics365].[dbo].[MX_Product_MinMax_Price_Vendor_Stock]
  where  CONS+[Min]+[Max]+[Stock]<>0
  and [STORECODE] not in ('WH0001','WH0002')
GO
/****** Object:  View [dbo].[vw_Drug_Batch_Stock_ordered_SUM_800STORE]    Script Date: 30/07/2025 12:27:44 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO

create view  [dbo].[vw_Drug_Batch_Stock_ordered_SUM_800STORE]
as
SELECT [ItemNumber]
      ,[Drug_id]
      ,[Stock]
      ,[Ordered]
      ,[SiteID]
      ,[Locationid]
  FROM [MarinaDynamics365].[dbo].[vw_Drug_Batch_Stock_ordered_SUM]
  where Locationid=51

GO
/****** Object:  View [dbo].[vw_D365_fConsumption_Final]    Script Date: 30/07/2025 12:27:44 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE VIEW [dbo].[vw_D365_fConsumption_Final]
AS
SELECT        dbo.D365_fConsumption.RequestedReceiptDate, dbo.D365_fConsumption.ItemNumber, dbo.D365_fConsumption.ShippingWarehouseId, dbo.D365_fConsumption.SalesUnitSymbol, 
                         dbo.D365_fConsumption.OrderedSalesQuantity AS OrderedSalesQuantity_, 
                         CASE WHEN dbo.D365_fConsumption.SalesUnitSymbol = 'Pcs' THEN dbo.D365_fConsumption.OrderedSalesQuantity / dbo.Mx_Product_Master_new.Factor ELSE dbo.D365_fConsumption.OrderedSalesQuantity END AS OrderedSalesQuantity,
                          dbo.Mx_Product_Master_new.Factor
FROM            dbo.D365_fConsumption LEFT OUTER JOIN
                         dbo.Mx_Product_Master_new ON dbo.D365_fConsumption.ItemNumber = dbo.Mx_Product_Master_new.ItemNumber
GO
/****** Object:  Table [dbo].[TransferOrder_Pending_Sum_created]    Script Date: 30/07/2025 12:27:44 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[TransferOrder_Pending_Sum_created](
	[ReceivingWarehouseId] [nvarchar](max) NULL,
	[ItemNumber] [nvarchar](max) NULL,
	[Pending_Qty] [float] NOT NULL
) ON [PRIMARY] TEXTIMAGE_ON [PRIMARY]
GO
/****** Object:  Table [dbo].[TransferOrder_Pending_Sum_shipped]    Script Date: 30/07/2025 12:27:44 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[TransferOrder_Pending_Sum_shipped](
	[ReceivingWarehouseId] [nvarchar](max) NULL,
	[ItemNumber] [nvarchar](max) NULL,
	[Pending_Qty] [float] NULL
) ON [PRIMARY] TEXTIMAGE_ON [PRIMARY]
GO
/****** Object:  View [dbo].[vw_Branch_Replenisment_final_view_Items_Branch_upload]    Script Date: 30/07/2025 12:27:44 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE VIEW [dbo].[vw_Branch_Replenisment_final_view_Items_Branch_upload] AS
    SELECT 
        loc.STORECODE, 
        loc.ItemNumber, 
        loc.ShortName, 
        loc.ProductName, 
        loc.ProductGroupId, 
        ISNULL(brc.Qty_Sold, 0) AS Cos, 
        ISNULL(dbs.Stock, 0) AS Stock, 
        ISNULL(dbs.Ordered, 0) AS Intransit, 
        ISNULL(dbs.Stock, 0) + ISNULL(dbs.Ordered, 0) AS TotalStock, 
        ISNULL(wh.Stock, 0) AS WHStock, 
        ISNULL(wh.Ordered, 0) AS WHInTransit, 
		
        round(ISNULL(brc.Qty_Sold, 0) / 91 * 60  
            - (ISNULL(dbs.Stock, 0) + ISNULL(dbs.Ordered, 0)),0) AS Req_Order, 
			      ISNULL(brc.Qty_Sold, 0) / 91 * 60  
            - (ISNULL(dbs.Stock, 0) + ISNULL(dbs.Ordered, 0)) AS Req_Order_raw, 

        pm.Selling_Price, 
        ISNULL(brm.Max_Qty_Sold, 0) AS MaxQtySold, 
        ISNULL(tolr.ReceivedQuantity, 0) AS Last_Rec_Qty, 
        tolr.RequestedReceiptDate AS Last_Rec_Date,
        60  AS [Req. Days],
	          ISNULL(dbo.Mx_Min_Max_Raw_Upload.Min, '0') AS Min, ISNULL(dbo.Mx_Min_Max_Raw_Upload.Max, '0') AS Max
			    , dbo.Lastest_Sales_per_item_Branch.Billdate AS Last_Sales_date, 
                         dbo.Lastest_Sales_per_item_Branch.Qty_Sold AS Last_Sales_qty
						  , dbo.TransferOrderLines_Pending_InBR2WH_Transit_SUM.Qty as br2wh_Instransit
						  , dbo.PurchaseOrder_Status_sum.RequestedDeliveryDate AS Pending_LPO_Date
						  , ISNULL(dbo.PurchaseOrder_Status_sum.OrderedPurchaseQuantity, 0) AS Pending_LPO_Qty
						    , ISNULL(dbo.PurchaseOrder_Status_sum.Remaining, 0) AS Pending_LPO_Qty_Lacking
   FROM 
        dbo.Mx_Product_Master_new_w_location AS loc
        INNER JOIN dbo.Mx_PriceMaster AS pm ON loc.ItemNumber = pm.Item
			LEFT OUTER JOIN
                         dbo.TransferOrder_Pending_Sum_shipped ON loc.STORECODE = dbo.TransferOrder_Pending_Sum_shipped.ReceivingWarehouseId AND 
                         loc.ItemNumber = dbo.TransferOrder_Pending_Sum_shipped.ItemNumber LEFT OUTER JOIN
                         dbo.TransferOrder_Pending_Sum_created ON loc.STORECODE = dbo.TransferOrder_Pending_Sum_created.ReceivingWarehouseId AND 
                         loc.ItemNumber = dbo.TransferOrder_Pending_Sum_created.ItemNumber
		 LEFT OUTER JOIN
                         dbo.PurchaseOrder_Status_sum ON loc.ItemNumber = dbo.PurchaseOrder_Status_sum.ItemNumber
		LEFT OUTER JOIN
                         dbo.TransferOrderLines_Pending_InBR2WH_Transit_SUM ON loc.ItemNumber = dbo.TransferOrderLines_Pending_InBR2WH_Transit_SUM.ItemNumber
		LEFT OUTER JOIN
                         dbo.Lastest_Sales_per_item_Branch ON loc.ItemNumber = dbo.Lastest_Sales_per_item_Branch.ItemNumber AND loc.LocationID = dbo.Lastest_Sales_per_item_Branch.LocationID 

		LEFT OUTER JOIN
                         dbo.Mx_Min_Max_Raw_Upload ON loc.ItemNumber = dbo.Mx_Min_Max_Raw_Upload.ItemNumber AND loc.STORECODE = dbo.Mx_Min_Max_Raw_Upload.SiteCode 
        LEFT JOIN dbo.TransferOrders_Latest_Received AS tolr 
            ON loc.ItemNumber = tolr.ItemNumber 
            AND loc.STORECODE = tolr.ReceivingWarehouseId
        LEFT JOIN dbo.Branch_Replenishment_Max_QtySold AS brm 
            ON loc.ItemNumber = brm.ItemNumber 
            AND loc.LocationID = brm.LocationID
        LEFT JOIN dbo.vw_Drug_Batch_Stock_ordered_SUM_PUR_WH AS wh 
            ON loc.ItemNumber = wh.ItemNumber
        LEFT JOIN dbo.Drug_Batch_Stock_ordered_SUM_PUR AS dbs 
            ON loc.ItemNumber = dbs.ItemNumber 
            AND loc.LocationID = dbs.LocationID
        LEFT JOIN dbo.Branch_Replenishment_Cons_Sum AS brc 
            ON loc.ItemNumber = brc.ItemNumber 
            AND loc.LocationID = brc.LocationID
    WHERE 
        loc.STORECODE NOT IN ('WH0001', 'WH0002')
		 AND loc.ShortName in ( SELECT  dbo.udftrim([Column1])
     
  FROM [MarinaDynamics365].[dbo].[Branch_Replenishment_branch] )

        AND loc.ItemNumber in ( SELECT  [Column1]
     
  FROM [MarinaDynamics365].[dbo].[Branch_Replenishment_itemnumberList])
  
GO
/****** Object:  View [dbo].[vw_Drug_Batch_Stock_ordered_SUM_orig]    Script Date: 30/07/2025 12:27:44 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO









create view [dbo].[vw_Drug_Batch_Stock_ordered_SUM_orig]
as

  SELECT [ItemId] ItemNumber
  ,(Select Drug_id  FROM [MarinaDynamics365].[dbo].[Mx_Product_Master_new] dm
where dm.ItemNumber=i.[ItemId] ) Drug_id
  ,sum([AvailPhysical]) Stock
	   ,sum([Ordered]) Ordered
	    ,[InventDim_InventSiteId] SiteID
		 ,(select Locationid from [MarinaDynamics365].dbo.Mx_StoreCode s
	  where s.STORECODE=i.[InventDim_InventSiteId]) Locationid

  FROM [MarinaDynamics365].[dbo].[HSInventSums] i
  where InventDim_wMSLocationId='Storage'

   group by [ItemId]
  ,[InventDim_InventSiteId] 
GO
/****** Object:  Table [dbo].[SalesPriceAgreements]    Script Date: 30/07/2025 12:27:44 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[SalesPriceAgreements](
	[PriceApplicableFromDate] [varchar](255) NULL,
	[SalesPriceQuantity] [int] NULL,
	[ProductNumber] [int] NULL,
	[ItemNumber] [int] NULL,
	[PriceApplicableToDate] [varchar](255) NULL,
	[PriceCustomerGroupCode] [varchar](255) NULL,
	[Price] [float] NULL
) ON [PRIMARY]
GO
/****** Object:  View [dbo].[vw_SalesAgreement_LatestPrice]    Script Date: 30/07/2025 12:27:44 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
create view [dbo].[vw_SalesAgreement_LatestPrice]
as

WITH RankedPrices AS (
    SELECT
        [ItemNumber],
        [PriceApplicableFromDate],
        [PriceApplicableToDate],
        [PriceCustomerGroupCode],
        [Price],
		QuantityUnitySymbol,
        ROW_NUMBER() OVER (
            PARTITION BY [ItemNumber], [PriceCustomerGroupCode]
            ORDER BY [PriceApplicableFromDate] DESC, [PriceApplicableToDate] DESC
        ) as rn
    FROM
        [MarinaDynamics365].[dbo].[SalesPriceAgreements]
		where QuantityUnitySymbol not like 'P%c%s'
)
SELECT
    [ItemNumber],
    [PriceApplicableFromDate],
    [PriceApplicableToDate],
    [PriceCustomerGroupCode],
    [Price],
	QuantityUnitySymbol
FROM
    RankedPrices
WHERE
    rn = 1;
GO
/****** Object:  Table [dbo].[SALES_ZERO_STOCK_REF_COMBINED_6mos]    Script Date: 30/07/2025 12:27:44 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[SALES_ZERO_STOCK_REF_COMBINED_6mos](
	[ItemNumber] [varchar](50) NULL,
	[LocationID] [int] NOT NULL,
	[Qty_Sold] [money] NULL
) ON [PRIMARY]
GO
/****** Object:  View [dbo].[vw_MIN_MAX_REFERENCE_CALCULATOR]    Script Date: 30/07/2025 12:27:44 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE VIEW [dbo].[vw_MIN_MAX_REFERENCE_CALCULATOR]
AS
SELECT        dbo.Mx_Product_Master_new_w_location.ItemNumber, dbo.Mx_Product_Master_new_w_location.Drug_id, dbo.Mx_Product_Master_new_w_location.ProductName, dbo.Mx_Product_Master_new_w_location.STORECODE, 
                         dbo.Mx_Product_Master_new_w_location.LocationID, ISNULL(dbo.SALES_ZERO_STOCK_REF_COMBINED_6mos.Qty_Sold, 0) AS [6MOS], ISNULL(dbo.SALES_ZERO_STOCK_REF_COMBINED_60days.Qty_Sold, 0) AS [2M], 
                         ISNULL(dbo.Drug_Batch_Stock_ordered_SUM.Stock, 0) AS Stock, dbo.MX_Product_MinMax_Price_Vendor_Stock.Min, dbo.MX_Product_MinMax_Price_Vendor_Stock.Max, 
                         dbo.Mx_Product_Master_new_w_location.ShortName
FROM            dbo.Mx_Product_Master_new_w_location LEFT OUTER JOIN
                         dbo.MX_Product_MinMax_Price_Vendor_Stock ON dbo.Mx_Product_Master_new_w_location.LocationID = dbo.MX_Product_MinMax_Price_Vendor_Stock.LocationID AND 
                         dbo.Mx_Product_Master_new_w_location.ItemNumber = dbo.MX_Product_MinMax_Price_Vendor_Stock.ItemNumber LEFT OUTER JOIN
                         dbo.Drug_Batch_Stock_ordered_SUM ON dbo.Mx_Product_Master_new_w_location.ItemNumber = dbo.Drug_Batch_Stock_ordered_SUM.ItemNumber AND 
                         dbo.Mx_Product_Master_new_w_location.LocationID = dbo.Drug_Batch_Stock_ordered_SUM.Locationid LEFT OUTER JOIN
                         dbo.SALES_ZERO_STOCK_REF_COMBINED_60days ON dbo.Mx_Product_Master_new_w_location.ItemNumber = dbo.SALES_ZERO_STOCK_REF_COMBINED_60days.ItemNumber AND 
                         dbo.Mx_Product_Master_new_w_location.LocationID = dbo.SALES_ZERO_STOCK_REF_COMBINED_60days.LocationID LEFT OUTER JOIN
                         dbo.SALES_ZERO_STOCK_REF_COMBINED_6mos ON dbo.Mx_Product_Master_new_w_location.ItemNumber = dbo.SALES_ZERO_STOCK_REF_COMBINED_6mos.ItemNumber AND 
                         dbo.Mx_Product_Master_new_w_location.LocationID = dbo.SALES_ZERO_STOCK_REF_COMBINED_6mos.LocationID
GO
/****** Object:  View [dbo].[vw_SalesAgreement_UAE_HTL]    Script Date: 30/07/2025 12:27:44 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
create view [dbo].[vw_SalesAgreement_UAE_HTL]
as


WITH PivotedPrices AS (
    SELECT
        pvt.[ItemNumber],
        MAX(CASE WHEN pvt.[PriceCustomerGroupCode] = 'UAE-HTL' THEN pvt.[PriceApplicableFromDate] END) AS [HTL_PriceApplicableFromDate],
        MAX(CASE WHEN pvt.[PriceCustomerGroupCode] = 'UAE-HTL' THEN pvt.[PriceApplicableToDate] END) AS [HTL_PriceApplicableToDate],
        MAX(CASE WHEN pvt.[PriceCustomerGroupCode] = 'UAE-HTL' THEN pvt.[Price] END) AS [HTL_Price],
        MAX(CASE WHEN pvt.[PriceCustomerGroupCode] = 'UAE-RETAIL' THEN pvt.[PriceApplicableFromDate] END) AS [RETAIL_PriceApplicableFromDate],
        MAX(CASE WHEN pvt.[PriceCustomerGroupCode] = 'UAE-RETAIL' THEN pvt.[PriceApplicableToDate] END) AS [RETAIL_PriceApplicableToDate],
        MAX(CASE WHEN pvt.[PriceCustomerGroupCode] = 'UAE-RETAIL' THEN pvt.[Price] END) AS [RETAIL_Price]
    FROM
        [MarinaDynamics365].[dbo].[vw_SalesAgreement_LatestPrice] pvt
    WHERE
        pvt.[PriceCustomerGroupCode] IN ('UAE-HTL', 'UAE-RETAIL')
    GROUP BY
        pvt.[ItemNumber]
)
SELECT
    [ItemNumber],
    [HTL_PriceApplicableFromDate],
    [HTL_PriceApplicableToDate],
    [HTL_Price],
    [RETAIL_PriceApplicableFromDate],
    [RETAIL_PriceApplicableToDate],
    [RETAIL_Price]
FROM
    PivotedPrices
WHERE
    [HTL_Price] <> [RETAIL_Price]
    OR [HTL_Price] IS NULL -- Include items where one price exists but the other doesn't (difference effectively not zero)
    OR [RETAIL_Price] IS NULL; -- Include items where one price exists but the other doesn't
GO
/****** Object:  View [dbo].[vw_LPO_Details_Export_To_253]    Script Date: 30/07/2025 12:27:44 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO








  create view [dbo].[vw_LPO_Details_Export_To_253]
  as
SELECT 
       [PurchaseOrderNumber]
	    ,[ItemNumber]
	   ,(select productname from MarinaDynamics365.dbo.Mx_Product_Master_new p
	   where p.ItemNumber=v.ItemNumber) [LineDescription]
	   ,[OrderedPurchaseQuantity]
	   ,case when PurchasePrice=0 then [OrderedPurchaseQuantity] else 0 end Bonus
	   ,'' [Remarks]
      ,'D365' [sessionid]
      ,0 [Total_Del]
      ,'' [isLacking]
      ,'' [Order_id]
      ,0 [Qty_Del]
      ,0 [Bonus_Del]
      ,0 [Qty_Del_Actual]
      ,0 [Bonus_Del_Actual]
      ,'' [Lacking_Remarks_Item]
      ,GETDATE() [Last_Update_ff]
      ,GETDATE() [Last_Updated]
      ,'' [Last_Update_mgt]
      ,GETDATE() [Last_Updated_date_mgt]
      ,''[Last_Update_mgt_user]
      ,''[Archived_by]
      ,GETDATE()[Archive_Date]
      ,'' [Item_Status]
      , round(LineAmount + (LineAmount * case when SalesTaxItemGroupCode='Standard' then .05 else 0 end),2) [item_order_value]
      ,PurchasePrice [UnitCost]
      ,'' [br_rcv_qty_temp]
      ,'' [br_rcv_qty_final]
	   ,case when PurchasePrice=0 then 'Yes' else 'No' end FOC
	   ,PurchaseUnitSymbol
	   ,LineDiscountAmount
	   ,SalesTaxItemGroupCode
	   ,case when SalesTaxItemGroupCode='Standard' then .05 else 0 end TaxPercent

	   , round(LineAmount * case when SalesTaxItemGroupCode='Standard' then .05 else 0 end,2) VAT
	   
	   ,LineNumber
	 ,  PurchaseOrderLineStatus
    FROM [MarinaDynamics365].[dbo].[PurchaseOrderLinesV2] v
	WHERE [PurchaseOrderNumber]  IN (SELECT [PurchaseOrderNumber]  FROM [MarinaDynamics365].[dbo].[vw_LPO_Master_export_to_253]
	WHERE [AccountingDate] >='2025-01-01')
GO
/****** Object:  View [dbo].[vw_Mx_Product_Category]    Script Date: 30/07/2025 12:27:44 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE VIEW [dbo].[vw_Mx_Product_Category]
AS
SELECT DISTINCT 
                         dbo.Mx_Product_Master_new.ItemNumber, dbo.Mx_Product_Master_new.ProductName, dbo.ProductCategoryAssignments.ProductCategoryName AS Marina_Brand, 
                         ProductCategoryAssignments_1.ProductCategoryName AS New_Category, ProductCategoryAssignments_2.ProductCategoryName AS Marina_Old_Category, dbo.Mx_Product_Master_new.Drug_id AS Old_Marina_ID
FROM            dbo.ProductCategoryAssignments AS ProductCategoryAssignments_1 RIGHT OUTER JOIN
                         dbo.Mx_Product_Master_new ON ProductCategoryAssignments_1.ProductNumber = dbo.Mx_Product_Master_new.ItemNumber LEFT OUTER JOIN
                         dbo.ProductCategoryAssignments AS ProductCategoryAssignments_2 ON dbo.Mx_Product_Master_new.ItemNumber = ProductCategoryAssignments_2.ProductNumber LEFT OUTER JOIN
                         dbo.ProductCategoryAssignments ON dbo.Mx_Product_Master_new.ItemNumber = dbo.ProductCategoryAssignments.ProductNumber
WHERE        (dbo.ProductCategoryAssignments.ProductCategoryHierarchyName = N'Marina_Brand') AND (ProductCategoryAssignments_1.ProductCategoryHierarchyName = N'MARINA PHARMACY') AND 
                         (ProductCategoryAssignments_2.ProductCategoryHierarchyName = N'Marina_Old_Category')
GO
/****** Object:  Table [dbo].[Expiry_Upload_w_ExpirationDate_RAW]    Script Date: 30/07/2025 12:27:44 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[Expiry_Upload_w_ExpirationDate_RAW](
	[Item number] [varchar](50) NULL,
	[Product name] [varchar](254) NULL,
	[Consignment item] [varchar](50) NULL,
	[Bonus Item] [varchar](50) NULL,
	[Warehouse] [varchar](50) NULL,
	[Batch number] [varchar](50) NULL,
	[Location] [varchar](50) NULL,
	[Warehouse Name] [varchar](50) NULL,
	[Primary Vendor] [varchar](50) NULL,
	[Vendor Name] [varchar](254) NULL,
	[Batch disposition code] [varchar](50) NULL,
	[Batch disposition status] [varchar](50) NULL,
	[Manufacturing date] [varchar](50) NULL,
	[Shelf life period in days] [varchar](50) NULL,
	[Expiration date] [varchar](50) NULL,
	[Physical inventory] [varchar](50) NULL,
	[Physical reserved] [varchar](50) NULL,
	[Available physical] [varchar](50) NULL,
	[Ordered] [varchar](50) NULL,
	[Ordered reserved] [varchar](50) NULL,
	[Total available] [varchar](50) NULL
) ON [PRIMARY]
GO
/****** Object:  View [dbo].[vw_Drug_Batch_Stock_COMBINED_D365_Expiry]    Script Date: 30/07/2025 12:27:44 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO



create view [dbo].[vw_Drug_Batch_Stock_COMBINED_D365_Expiry]
as
SELECT  [Item number] +[Warehouse]+[Batch number] [BatchID]
      	 , [Item number] [Drug_id]
         ,[Batch number] [Batch_No]
	   ,[dbo].[DateConvertShort_Long]([Expiration date]) [ExpDate]
	   ,cast([Available physical] as float) Stock
	   ,(select locationid from MarinaDynamics365.dbo.Mx_StoreCode s
	   where s.STORECODE=e.[Warehouse]) LocationID
	  ,[Warehouse]
      FROM [MarinaDynamics365].[dbo].[Expiry_Upload_w_ExpirationDate_RAW] e
where [location]='Storage'
GO
/****** Object:  View [dbo].[vw_FEB2024_REORDER_PIVOT]    Script Date: 30/07/2025 12:27:44 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE VIEW [dbo].[vw_FEB2024_REORDER_PIVOT]
AS  Select [Item Number],[Product Name] ,isnull([800 PARK],0) QTY,
53 locationid FROM [MarinaDynamics365].[dbo].[FEB2024_REORDER_TO_D365] union  Select [Item Number],[Product Name] ,isnull([GLDMILE2],0) QTY,
24 locationid FROM [MarinaDynamics365].[dbo].[FEB2024_REORDER_TO_D365] union  Select [Item Number],[Product Name] ,isnull([800ARJAN],0) QTY,
82 locationid FROM [MarinaDynamics365].[dbo].[FEB2024_REORDER_TO_D365] union  Select [Item Number],[Product Name] ,isnull([800CRCLE],0) QTY,
62 locationid FROM [MarinaDynamics365].[dbo].[FEB2024_REORDER_TO_D365] union  Select [Item Number],[Product Name] ,isnull([800 DHCC],0) QTY,
52 locationid FROM [MarinaDynamics365].[dbo].[FEB2024_REORDER_TO_D365] union  Select [Item Number],[Product Name] ,isnull([800ALQUZ],0) QTY,
64 locationid FROM [MarinaDynamics365].[dbo].[FEB2024_REORDER_TO_D365] union  Select [Item Number],[Product Name] ,isnull([800 CENT],0) QTY,
56 locationid FROM [MarinaDynamics365].[dbo].[FEB2024_REORDER_TO_D365] union  Select [Item Number],[Product Name] ,isnull([800CAPTL],0) QTY,
63 locationid FROM [MarinaDynamics365].[dbo].[FEB2024_REORDER_TO_D365] union  Select [Item Number],[Product Name] ,isnull([CARE],0) QTY,
18 locationid FROM [MarinaDynamics365].[dbo].[FEB2024_REORDER_TO_D365] union  Select [Item Number],[Product Name] ,isnull([CARE 2],0) QTY,
93 locationid FROM [MarinaDynamics365].[dbo].[FEB2024_REORDER_TO_D365] union  Select [Item Number],[Product Name] ,isnull([CARE 1],0) QTY,
84 locationid FROM [MarinaDynamics365].[dbo].[FEB2024_REORDER_TO_D365] union  Select [Item Number],[Product Name] ,isnull([CARE 3],0) QTY,
94 locationid FROM [MarinaDynamics365].[dbo].[FEB2024_REORDER_TO_D365] union  Select [Item Number],[Product Name] ,isnull([OLDTOWN],0) QTY,
55 locationid FROM [MarinaDynamics365].[dbo].[FEB2024_REORDER_TO_D365] union  Select [Item Number],[Product Name] ,isnull([CWALK1],0) QTY,
61 locationid FROM [MarinaDynamics365].[dbo].[FEB2024_REORDER_TO_D365] union  Select [Item Number],[Product Name] ,isnull([CENTER],0) QTY,
30 locationid FROM [MarinaDynamics365].[dbo].[FEB2024_REORDER_TO_D365] union  Select [Item Number],[Product Name] ,isnull([PALM],0) QTY,
60 locationid FROM [MarinaDynamics365].[dbo].[FEB2024_REORDER_TO_D365] union  Select [Item Number],[Product Name] ,isnull([AVENUE],0) QTY,
33 locationid FROM [MarinaDynamics365].[dbo].[FEB2024_REORDER_TO_D365] union  Select [Item Number],[Product Name] ,isnull([PROMINAD],0) QTY,
65 locationid FROM [MarinaDynamics365].[dbo].[FEB2024_REORDER_TO_D365] 
GO
/****** Object:  Table [dbo].[Branch_Replenishment_Category]    Script Date: 30/07/2025 12:27:44 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[Branch_Replenishment_Category](
	[Column1] [varchar](50) NULL,
	[NewValue] [varchar](50) NULL
) ON [PRIMARY]
GO
/****** Object:  View [dbo].[vw_Branch_Replenisment_final_view]    Script Date: 30/07/2025 12:27:44 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO

    CREATE VIEW [dbo].[vw_Branch_Replenisment_final_view] AS
    SELECT 
        loc.STORECODE, 
        loc.ItemNumber, 
        loc.ShortName, 
        loc.ProductName, 
        loc.ProductGroupId, 
        ISNULL(brc.Qty_Sold, 0) AS Cos, 
        ISNULL(dbs.Stock, 0) AS Stock, 
        ISNULL(dbs.Ordered, 0) AS Intransit, 
        ISNULL(dbs.Stock, 0) + ISNULL(dbs.Ordered, 0) AS TotalStock, 
        ISNULL(wh.Stock, 0) AS WHStock, 
        ISNULL(wh.Ordered, 0) AS WHInTransit, 
        round(ISNULL(brc.Qty_Sold, 0) / 91 * 60 
            - (ISNULL(dbs.Stock, 0) + ISNULL(dbs.Ordered, 0)),0) AS Req_Order, 
			      ISNULL(brc.Qty_Sold, 0) / 91 * 60 
            - (ISNULL(dbs.Stock, 0) + ISNULL(dbs.Ordered, 0)) AS Req_Order_raw, 
        pm.Selling_Price, 
        ISNULL(brm.Max_Qty_Sold, 0) AS MaxQtySold, 
        ISNULL(tolr.ReceivedQuantity, 0) AS Last_Rec_Qty, 
        tolr.RequestedReceiptDate AS Last_Rec_Date,
        60 AS [Req. Days],
	          ISNULL(dbo.Mx_Min_Max_Raw_Upload.Min, '0') AS Min, ISNULL(dbo.Mx_Min_Max_Raw_Upload.Max, '0') AS Max
			    , dbo.Lastest_Sales_per_item_Branch.Billdate AS Last_Sales_date, dbo.Lastest_Sales_per_item_Branch.Qty_Sold AS Last_Sales_qty
						  , dbo.TransferOrderLines_Pending_InBR2WH_Transit_SUM.Qty as br2wh_Instransit, dbo.PurchaseOrder_Status_sum.RequestedDeliveryDate AS Pending_LPO_Date
						  , ISNULL(dbo.PurchaseOrder_Status_sum.OrderedPurchaseQuantity, 0) AS Pending_LPO_Qty
						  , ISNULL(dbo.PurchaseOrder_Status_sum.Remaining, 0) AS Pending_LPO_Qty_Lacking
						  ,dbo.TransferOrder_Pending_Sum_created.Pending_Qty AS TO_Created
						  , dbo.TransferOrder_Pending_Sum_shipped.Pending_Qty AS TO_Shifted    FROM 
        dbo.Mx_Product_Master_new_w_location AS loc
        INNER JOIN dbo.Mx_PriceMaster AS pm ON loc.ItemNumber = pm.Item
		LEFT OUTER JOIN
                         dbo.TransferOrder_Pending_Sum_shipped ON loc.STORECODE = dbo.TransferOrder_Pending_Sum_shipped.ReceivingWarehouseId AND 
                         loc.ItemNumber = dbo.TransferOrder_Pending_Sum_shipped.ItemNumber LEFT OUTER JOIN
                         dbo.TransferOrder_Pending_Sum_created ON loc.STORECODE = dbo.TransferOrder_Pending_Sum_created.ReceivingWarehouseId AND 
                         loc.ItemNumber = dbo.TransferOrder_Pending_Sum_created.ItemNumber
		 LEFT OUTER JOIN
                         dbo.PurchaseOrder_Status_sum ON loc.ItemNumber = dbo.PurchaseOrder_Status_sum.ItemNumber
		LEFT OUTER JOIN
                         dbo.TransferOrderLines_Pending_InBR2WH_Transit_SUM ON loc.ItemNumber = dbo.TransferOrderLines_Pending_InBR2WH_Transit_SUM.ItemNumber
		LEFT OUTER JOIN
                         dbo.Lastest_Sales_per_item_Branch ON loc.ItemNumber = dbo.Lastest_Sales_per_item_Branch.ItemNumber AND loc.LocationID = dbo.Lastest_Sales_per_item_Branch.LocationID 
		LEFT OUTER JOIN
                         dbo.Mx_Min_Max_Raw_Upload ON loc.ItemNumber = dbo.Mx_Min_Max_Raw_Upload.ItemNumber AND loc.STORECODE = dbo.Mx_Min_Max_Raw_Upload.SiteCode 
        LEFT JOIN dbo.TransferOrders_Latest_Received AS tolr 
            ON loc.ItemNumber = tolr.ItemNumber 
            AND loc.STORECODE = tolr.ReceivingWarehouseId
        LEFT JOIN dbo.Branch_Replenishment_Max_QtySold AS brm 
            ON loc.ItemNumber = brm.ItemNumber 
            AND loc.LocationID = brm.LocationID
        LEFT JOIN dbo.vw_Drug_Batch_Stock_ordered_SUM_PUR_WH AS wh 
            ON loc.ItemNumber = wh.ItemNumber
        LEFT JOIN dbo.Drug_Batch_Stock_ordered_SUM_PUR AS dbs 
            ON loc.ItemNumber = dbs.ItemNumber 
            AND loc.LocationID = dbs.LocationID
        LEFT JOIN dbo.Branch_Replenishment_Cons_Sum AS brc 
            ON loc.ItemNumber = brc.ItemNumber AND loc.LocationID = brc.LocationID
    WHERE loc.STORECODE NOT IN ('WH0001', 'WH0002')AND loc.ProductGroupId in ( SELECT  [Column1]
   FROM [MarinaDynamics365].[dbo].[Branch_Replenishment_Category]);
    
GO
/****** Object:  UserDefinedFunction [dbo].[RoundUpDown]    Script Date: 30/07/2025 12:27:44 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO





CREATE FUNCTION [dbo].[RoundUpDown] 
( 
    @qty float
) 
 
returns int
with schemabinding as begin

   
    RETURN CASE WHEN @qty>0 AND  @qty<1 THEN CEILING(@qty) WHEN  @qty>=1 THEN FLOOR( @qty)
	WHEN  @qty<0 THEN 0
	WHEN  @qty=0 THEN 0 END

	END

GO
/****** Object:  UserDefinedFunction [dbo].[SplitStringToColumns]    Script Date: 30/07/2025 12:27:44 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE FUNCTION [dbo].[SplitStringToColumns]
(
    @InputString NVARCHAR(MAX),
    @Delimiter CHAR(1)
)
RETURNS TABLE
AS
RETURN
WITH SplitString AS
(
    SELECT
        CAST('<x>' + REPLACE(REPLACE(REPLACE(REPLACE(@InputString, '&', '&amp;'), '<', '&lt;'), '>', '&gt;'), @Delimiter, '</x><x>') + '</x>' AS XML) AS XmlData
)
SELECT
    XmlData.value('/x[1]', 'NVARCHAR(MAX)') AS Part1,
    XmlData.value('/x[2]', 'NVARCHAR(MAX)') AS Part2,
    XmlData.value('/x[3]', 'NVARCHAR(MAX)') AS Part3,
    XmlData.value('/x[4]', 'NVARCHAR(MAX)') AS Part4,
    XmlData.value('/x[5]', 'NVARCHAR(MAX)') AS Part5,
    XmlData.value('/x[6]', 'NVARCHAR(MAX)') AS Part6,
    XmlData.value('/x[7]', 'NVARCHAR(MAX)') AS Part7,
    XmlData.value('/x[8]', 'NVARCHAR(MAX)') AS Part8,
    XmlData.value('/x[9]', 'NVARCHAR(MAX)') AS Part9,
    XmlData.value('/x[10]', 'NVARCHAR(MAX)') AS Part10
FROM SplitString;

GO
/****** Object:  Table [dbo].[AllProducts]    Script Date: 30/07/2025 12:27:44 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[AllProducts](
	[ProductNumber] [nvarchar](max) NULL,
	[ProductDescription] [nvarchar](max) NULL,
	[ProductName] [nvarchar](max) NULL,
	[ProductSearchName] [nvarchar](max) NULL
) ON [PRIMARY] TEXTIMAGE_ON [PRIMARY]
GO
/****** Object:  Table [dbo].[Branch_Replenishment_Cons_Sum_Order]    Script Date: 30/07/2025 12:27:44 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[Branch_Replenishment_Cons_Sum_Order](
	[ItemNumber] [nchar](10) NULL,
	[Qty_Sold] [money] NULL
) ON [PRIMARY]
GO
/****** Object:  Table [dbo].[Branch_Replenishment_Max_QtySold_All_branch]    Script Date: 30/07/2025 12:27:44 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[Branch_Replenishment_Max_QtySold_All_branch](
	[ItemNumber] [nchar](10) NULL,
	[Max_Qty_Sold] [money] NULL
) ON [PRIMARY]
GO
/****** Object:  Table [dbo].[Branch_Replenisment_final_view]    Script Date: 30/07/2025 12:27:44 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[Branch_Replenisment_final_view](
	[StoreCode] [varchar](50) NULL,
	[ItemNumber] [nvarchar](max) NULL,
	[Branch] [varchar](50) NULL,
	[ProductName] [nvarchar](max) NULL,
	[Category] [nvarchar](max) NULL,
	[Cos] [money] NOT NULL,
	[Stock] [float] NOT NULL,
	[Intransit] [float] NOT NULL,
	[TotalStock] [float] NOT NULL,
	[WHStock] [float] NOT NULL,
	[WHInTransit] [float] NOT NULL,
	[Req_Order] [float] NULL,
	[Req_Order_raw] [float] NULL,
	[Req_Order_Raw2] [float] NULL,
	[RSP] [varchar](50) NULL,
	[MaxQtySold] [money] NOT NULL,
	[Last_Rec_Qty] [float] NOT NULL,
	[Last_Rec_Date] [date] NULL,
	[Sales_Days] [int] NOT NULL,
	[Req. Days] [int] NOT NULL,
	[Min] [varchar](50) NOT NULL,
	[Max] [varchar](50) NOT NULL,
	[Last_Sales_date] [date] NULL,
	[Last_Sales_qty] [money] NULL,
	[br2wh_Instransit] [float] NOT NULL,
	[Pending_LPO_Date] [date] NULL,
	[Pending_LPO_Qty] [float] NOT NULL,
	[TO_Created] [float] NOT NULL,
	[TO_Shipped] [float] NOT NULL,
	[Remaining] [float] NOT NULL,
	[BR_Stk_Days] [float] NULL,
	[Actual_P_L] [float] NOT NULL,
	[WH_Location_Name] [varchar](50) NULL
) ON [PRIMARY] TEXTIMAGE_ON [PRIMARY]
GO
/****** Object:  Table [dbo].[CDSPurchaseOrderLines]    Script Date: 30/07/2025 12:27:44 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[CDSPurchaseOrderLines](
	[dataAreaId] [nvarchar](max) NULL,
	[PurchaseOrderNumber] [nvarchar](max) NULL,
	[LineNumber] [bigint] NULL,
	[CustomerReference] [nvarchar](max) NULL,
	[WorkflowState] [nvarchar](max) NULL,
	[ProductConfigurationId] [nvarchar](max) NULL,
	[PurchaseUnitSymbol] [nvarchar](max) NULL,
	[RequesterPersonnelNumber] [nvarchar](max) NULL,
	[DeliveryAddressName] [nvarchar](max) NULL,
	[LineDescription] [nvarchar](max) NULL,
	[ProductNumber] [nvarchar](max) NULL,
	[RequestedShippingDate] [datetime2](0) NULL,
	[DeliveryAddressStreetNumber] [nvarchar](max) NULL,
	[ProductSizeId] [nvarchar](max) NULL,
	[ProcurementProductCategoryHierachyName] [nvarchar](max) NULL,
	[ProductVersionId] [nvarchar](max) NULL,
	[ProductName] [nvarchar](max) NULL,
	[CatchWeightUnitSymbol] [nvarchar](max) NULL,
	[RequestedDeliveryDate] [datetime2](0) NULL,
	[CustomerRequisitionNumber] [nvarchar](max) NULL,
	[DeliveryAddressZipCode] [nvarchar](max) NULL,
	[ReceivingSiteId] [nvarchar](max) NULL,
	[DeliveryAddressLocationId] [nvarchar](max) NULL,
	[PurchasePriceQuantity] [float] NULL,
	[CurrencyCode] [nvarchar](max) NULL,
	[OrderedInventoryStatusId] [nvarchar](max) NULL,
	[DeliveryAddressDescription] [nvarchar](max) NULL,
	[DeliveryAddressCountryRegionId] [nvarchar](max) NULL,
	[OrderedCatchWeightQuantity] [float] NULL,
	[LineAmount] [float] NULL,
	[LineDiscountPercentage] [float] NULL,
	[ExternalItemNumber] [nvarchar](max) NULL,
	[ConfirmedShippingDate] [datetime2](0) NULL,
	[OrderedPurchaseQuantity] [float] NULL,
	[ReceivingWarehouseId] [nvarchar](max) NULL,
	[ProcurementProductCategoryName] [nvarchar](max) NULL,
	[ConfirmedDeliveryDate] [datetime2](0) NULL,
	[ItemBatchNumber] [nvarchar](max) NULL,
	[PurchaseOrderLineStatus] [nvarchar](max) NULL,
	[DeliveryAddressStreet] [nvarchar](max) NULL,
	[LineDiscountAmount] [float] NULL,
	[IsPartialDeliveryPrevented] [nvarchar](max) NULL,
	[PurchasePrice] [float] NULL,
	[ProductColorId] [nvarchar](max) NULL,
	[ProjectId] [nvarchar](max) NULL,
	[Barcode] [nvarchar](max) NULL,
	[DeliveryAddressCity] [nvarchar](max) NULL,
	[DeliveryAddressStateId] [nvarchar](max) NULL,
	[FormattedDelveryAddress] [nvarchar](max) NULL,
	[ProductStyleId] [nvarchar](max) NULL
) ON [PRIMARY] TEXTIMAGE_ON [PRIMARY]
GO
/****** Object:  Table [dbo].[CDSReleasedDistinctProducts]    Script Date: 30/07/2025 12:27:44 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[CDSReleasedDistinctProducts](
	[dataAreaId] [nvarchar](max) NULL,
	[ProductNumber] [nvarchar](max) NULL,
	[ProductType] [nvarchar](max) NULL,
	[WarrantyDurationTime] [bigint] NULL,
	[InventoryUnitSymbol] [nvarchar](max) NULL,
	[WarrantablePriceRangeBaseType] [nvarchar](max) NULL,
	[ProductConfigurationId] [nvarchar](max) NULL,
	[UpperWarrantablePriceRangeLimit] [float] NULL,
	[InventoryUnitDecimalPrecision] [bigint] NULL,
	[ProductSizeId] [nvarchar](max) NULL,
	[CurrencyCode] [nvarchar](max) NULL,
	[ItemNumber] [nvarchar](max) NULL,
	[ProductColorId] [nvarchar](max) NULL,
	[ProductVersionId] [nvarchar](max) NULL,
	[ProductStyleId] [nvarchar](max) NULL,
	[ServiceType] [nvarchar](max) NULL,
	[SalesPrice] [float] NULL,
	[WarrantyDurationTimeUnit] [nvarchar](max) NULL,
	[SalesUnitDecimalPrecision] [bigint] NULL,
	[FieldServiceProductType] [nvarchar](max) NULL,
	[UnitCost] [float] NULL,
	[IsCatchWeightProduct] [nvarchar](max) NULL,
	[SalesUnitSymbol] [nvarchar](max) NULL,
	[ProductDescription] [nvarchar](max) NULL,
	[LowerWarrantablePriceRangeLimit] [float] NULL,
	[ProductName] [nvarchar](max) NULL,
	[IsStockedProduct] [nvarchar](max) NULL
) ON [PRIMARY] TEXTIMAGE_ON [PRIMARY]
GO
/****** Object:  Table [dbo].[CRM_Error_Upload_Raw1]    Script Date: 30/07/2025 12:27:44 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[CRM_Error_Upload_Raw1](
	[Integration log id] [varchar](50) NULL,
	[Order_id] [varchar](50) NULL,
	[Order_source] [varchar](50) NULL,
	[Branch_name] [varchar](50) NULL,
	[Branch_id] [varchar](50) NULL,
	[Agent_name] [varchar](50) NULL,
	[Status] [varchar](50) NULL,
	[With_insurance] [varchar](50) NULL,
	[Patient_name] [varchar](50) NULL,
	[Driver] [varchar](50) NULL,
	[Schedule_date] [varchar](50) NULL,
	[Payment_method] [varchar](50) NULL,
	[Reference_number] [varchar](50) NULL,
	[Sub_total] [varchar](50) NULL,
	[Delivery_charges] [varchar](50) NULL,
	[Discount] [varchar](50) NULL,
	[CRM total] [varchar](50) NULL,
	[Header status] [varchar](50) NULL,
	[Latest status] [varchar](50) NULL,
	[Header remarks] [varchar](254) NULL,
	[Sales order] [varchar](50) NULL,
	[parnter_name] [varchar](150) NULL,
	[additional_charges] [varchar](50) NULL,
	[Settled] [varchar](50) NULL,
	[Voucher] [varchar](50) NULL,
	[SKU] [varchar](50) NULL,
	[Name] [varchar](254) NULL,
	[Quantity] [varchar](50) NULL,
	[Price_without_vat] [varchar](50) NULL,
	[Vat_value] [varchar](50) NULL,
	[Price_with_vat] [varchar](50) NULL,
	[Line discount] [varchar](50) NULL,
	[Vat] [varchar](50) NULL,
	[Line number] [varchar](50) NULL,
	[Line status] [varchar](50) NULL,
	[Line remarks] [varchar](50) NULL,
	[Batch] [varchar](50) NULL,
	[Expiry] [varchar](50) NULL
) ON [PRIMARY]
GO
/****** Object:  Table [dbo].[CRM_Error_Upload_Raw2]    Script Date: 30/07/2025 12:27:44 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[CRM_Error_Upload_Raw2](
	[Integration log id] [varchar](50) NULL,
	[Order_id] [varchar](50) NULL,
	[Order_source] [varchar](50) NULL,
	[Branch_name] [varchar](50) NULL,
	[Branch_id] [varchar](50) NULL,
	[Agent_name] [varchar](50) NULL,
	[Status] [varchar](50) NULL,
	[With_insurance] [varchar](50) NULL,
	[Patient_name] [varchar](50) NULL,
	[Driver] [varchar](50) NULL,
	[Schedule_date] [varchar](50) NULL,
	[Payment_method] [varchar](50) NULL,
	[Reference_number] [varchar](50) NULL,
	[Sub_total] [varchar](50) NULL,
	[Delivery_charges] [varchar](50) NULL,
	[Discount] [varchar](50) NULL,
	[CRM total] [varchar](50) NULL,
	[Header status] [varchar](50) NULL,
	[Latest status] [varchar](50) NULL,
	[Header remarks] [varchar](max) NULL,
	[Sales order] [varchar](254) NULL,
	[parnter_name] [varchar](254) NULL,
	[additional_charges] [varchar](50) NULL,
	[Settled] [varchar](50) NULL,
	[Voucher] [varchar](50) NULL,
	[SKU] [varchar](50) NULL,
	[Name] [varchar](254) NULL,
	[Quantity] [varchar](50) NULL,
	[Price_without_vat] [varchar](254) NULL,
	[Vat_value] [varchar](50) NULL,
	[Price_with_vat] [varchar](50) NULL,
	[Line discount] [varchar](50) NULL,
	[Vat] [varchar](50) NULL,
	[Line number] [varchar](50) NULL,
	[Line status] [varchar](50) NULL,
	[Line remarks] [varchar](50) NULL,
	[Batch] [varchar](50) NULL,
	[Expiry] [varchar](50) NULL
) ON [PRIMARY] TEXTIMAGE_ON [PRIMARY]
GO
/****** Object:  Table [dbo].[CRM_FAILD_INVOICE_UPLOAD_RAW1]    Script Date: 30/07/2025 12:27:44 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[CRM_FAILD_INVOICE_UPLOAD_RAW1](
	[Integration log id] [varchar](50) NULL,
	[Order_id] [varchar](50) NULL,
	[Order_source] [varchar](50) NULL,
	[Branch_name] [varchar](50) NULL,
	[Branch_id] [varchar](50) NULL,
	[Agent_name] [varchar](50) NULL,
	[Status] [varchar](50) NULL,
	[With_insurance] [varchar](50) NULL,
	[Patient_name] [varchar](50) NULL,
	[Driver] [varchar](50) NULL,
	[Schedule_date] [varchar](50) NULL,
	[Payment_method] [varchar](50) NULL,
	[Reference_number] [varchar](50) NULL,
	[Sub_total] [varchar](50) NULL,
	[Delivery_charges] [varchar](50) NULL,
	[Discount] [varchar](50) NULL,
	[CRM total] [varchar](50) NULL,
	[Header status] [varchar](50) NULL,
	[Latest status] [varchar](50) NULL,
	[Header remarks] [varchar](254) NULL,
	[Sales order] [varchar](50) NULL,
	[parnter_name] [varchar](50) NULL,
	[additional_charges] [varchar](50) NULL,
	[Settled] [varchar](50) NULL,
	[Voucher] [varchar](50) NULL,
	[SKU] [varchar](50) NULL,
	[Name] [varchar](254) NULL,
	[Quantity] [varchar](50) NULL,
	[Price_without_vat] [varchar](50) NULL,
	[Vat_value] [varchar](50) NULL,
	[Price_with_vat] [varchar](50) NULL,
	[Line discount] [varchar](50) NULL,
	[Vat] [varchar](50) NULL,
	[Line number] [varchar](50) NULL,
	[Line status] [varchar](50) NULL,
	[Line remarks] [varchar](50) NULL,
	[Batch] [varchar](50) NULL,
	[Expiry] [varchar](50) NULL
) ON [PRIMARY]
GO
/****** Object:  Table [dbo].[D365_EXPIRY_UPLOAD_CSV]    Script Date: 30/07/2025 12:27:44 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[D365_EXPIRY_UPLOAD_CSV](
	[Item number] [varchar](50) NULL,
	[Product name] [varchar](254) NULL,
	[Consignment item] [varchar](50) NULL,
	[Bonus Item] [varchar](50) NULL,
	[Warehouse] [varchar](50) NULL,
	[Batch number] [varchar](50) NULL,
	[Location] [varchar](50) NULL,
	[Warehouse Name] [varchar](50) NULL,
	[Primary Vendor] [varchar](50) NULL,
	[Vendor Name] [varchar](254) NULL,
	[Batch disposition code] [varchar](50) NULL,
	[Batch disposition status] [varchar](50) NULL,
	[Manufacturing date] [varchar](50) NULL,
	[Shelf life period in days] [varchar](50) NULL,
	[Expiration date] [varchar](50) NULL,
	[Physical inventory] [varchar](50) NULL,
	[Physical reserved] [varchar](50) NULL,
	[Available physical] [varchar](50) NULL,
	[Ordered] [varchar](50) NULL,
	[Ordered reserved] [varchar](50) NULL,
	[Total available] [varchar](50) NULL
) ON [PRIMARY]
GO
/****** Object:  Table [dbo].[D365_EXPIRY_UPLOAD_CSV_3005]    Script Date: 30/07/2025 12:27:44 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[D365_EXPIRY_UPLOAD_CSV_3005](
	[Item number] [varchar](50) NULL,
	[Product name] [varchar](254) NULL,
	[Consignment item] [varchar](50) NULL,
	[Bonus Item] [varchar](50) NULL,
	[Site] [varchar](50) NULL,
	[Warehouse] [varchar](50) NULL,
	[Batch number] [varchar](50) NULL,
	[Location] [varchar](50) NULL,
	[Warehouse Name] [varchar](50) NULL,
	[Primary Vendor] [varchar](50) NULL,
	[Vendor Name] [varchar](254) NULL,
	[Batch disposition code] [varchar](50) NULL,
	[Batch disposition status] [varchar](50) NULL,
	[Manufacturing date] [varchar](50) NULL,
	[Shelf life period in days] [varchar](50) NULL,
	[Expiration date] [varchar](50) NULL,
	[Physical inventory] [varchar](50) NULL,
	[Physical reserved] [varchar](50) NULL,
	[Available physical] [varchar](50) NULL,
	[Ordered] [varchar](50) NULL,
	[Ordered reserved] [varchar](50) NULL,
	[Total available] [varchar](50) NULL
) ON [PRIMARY]
GO
/****** Object:  Table [dbo].[D365_EXPIRY_UPLOAD_CSV_for_ORDER1]    Script Date: 30/07/2025 12:27:44 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[D365_EXPIRY_UPLOAD_CSV_for_ORDER1](
	[Item number] [varchar](50) NULL,
	[Product name] [varchar](254) NULL,
	[Consignment item] [varchar](50) NULL,
	[Bonus Item] [varchar](50) NULL,
	[Warehouse] [varchar](50) NULL,
	[Batch number] [varchar](50) NULL,
	[Location] [varchar](50) NULL,
	[Warehouse Name] [varchar](50) NULL,
	[Primary Vendor] [varchar](50) NULL,
	[Vendor Name] [varchar](254) NULL,
	[Batch disposition code] [varchar](50) NULL,
	[Batch disposition status] [varchar](50) NULL,
	[Manufacturing date] [varchar](50) NULL,
	[Shelf life period in days] [varchar](50) NULL,
	[Expiration date] [varchar](50) NULL,
	[Physical inventory] [varchar](50) NULL,
	[Physical reserved] [varchar](50) NULL,
	[Available physical] [varchar](50) NULL,
	[Ordered] [varchar](50) NULL,
	[Ordered reserved] [varchar](50) NULL,
	[Total available] [varchar](50) NULL
) ON [PRIMARY]
GO
/****** Object:  Table [dbo].[D365_EXPIRY_UPLOAD_CSV1]    Script Date: 30/07/2025 12:27:44 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[D365_EXPIRY_UPLOAD_CSV1](
	[Item number] [varchar](50) NULL,
	[Product name] [varchar](254) NULL,
	[Consignment item] [varchar](50) NULL,
	[Warehouse] [varchar](50) NULL,
	[Batch number] [varchar](50) NULL,
	[Location] [varchar](50) NULL,
	[Warehouse name] [varchar](50) NULL,
	[Batch disposition code] [varchar](50) NULL,
	[Batch disposition status] [varchar](50) NULL,
	[Manufacturing date] [varchar](50) NULL,
	[Shelf life period in days] [varchar](50) NULL,
	[Expiration date] [varchar](50) NULL,
	[Physical inventory] [varchar](50) NULL,
	[Physical reserved] [varchar](50) NULL,
	[Available physical] [varchar](50) NULL,
	[Ordered] [varchar](50) NULL,
	[Ordered reserved] [varchar](50) NULL,
	[Total available] [varchar](50) NULL
) ON [PRIMARY]
GO
/****** Object:  Table [dbo].[D365_EXPIRY_UPLOAD_CSV2]    Script Date: 30/07/2025 12:27:44 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[D365_EXPIRY_UPLOAD_CSV2](
	[Item number] [varchar](50) NULL,
	[Product name] [varchar](254) NULL,
	[Warehouse name] [varchar](50) NULL,
	[Site] [varchar](50) NULL,
	[Warehouse] [varchar](50) NULL,
	[Batch number] [varchar](50) NULL,
	[Location] [varchar](50) NULL,
	[Expiration date] [varchar](50) NULL,
	[Physical inventory] [varchar](50) NULL,
	[Physical reserved] [varchar](50) NULL,
	[Available physical] [varchar](50) NULL,
	[Ordered] [varchar](50) NULL,
	[Ordered reserved] [varchar](50) NULL,
	[Total available] [varchar](50) NULL
) ON [PRIMARY]
GO
/****** Object:  Table [dbo].[D365_EXPIRY_UPLOAD_CSV3]    Script Date: 30/07/2025 12:27:44 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[D365_EXPIRY_UPLOAD_CSV3](
	[Item number] [varchar](50) NULL,
	[Product name] [varchar](254) NULL,
	[Warehouse] [varchar](50) NULL,
	[Batch number] [varchar](50) NULL,
	[Location] [varchar](50) NULL,
	[Warehouse Name] [varchar](50) NULL,
	[Primary Vendor] [varchar](50) NULL,
	[Vendor Name] [varchar](254) NULL,
	[Physical inventory] [varchar](50) NULL,
	[Physical reserved] [varchar](50) NULL,
	[Available physical] [varchar](50) NULL,
	[Available physical on exact dimensions] [varchar](50) NULL,
	[Ordered in total] [varchar](50) NULL,
	[On order] [varchar](50) NULL,
	[Ordered reserved] [varchar](50) NULL,
	[Available for reservation] [varchar](50) NULL,
	[Total available] [varchar](50) NULL,
	[Uses warehouse management processes] [varchar](50) NULL,
	[Product identification] [varchar](50) NULL
) ON [PRIMARY]
GO
/****** Object:  Table [dbo].[D365_EXPIRY_UPLOAD_CSV4]    Script Date: 30/07/2025 12:27:44 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[D365_EXPIRY_UPLOAD_CSV4](
	[Item number] [varchar](50) NULL,
	[Product name] [varchar](254) NULL,
	[Consignment item] [varchar](50) NULL,
	[Bonus Item] [varchar](50) NULL,
	[Warehouse] [varchar](50) NULL,
	[Batch number] [varchar](50) NULL,
	[Location] [varchar](50) NULL,
	[Warehouse Name] [varchar](50) NULL,
	[Primary Vendor] [varchar](50) NULL,
	[Vendor Name] [varchar](254) NULL,
	[Batch disposition code] [varchar](50) NULL,
	[Batch disposition status] [varchar](50) NULL,
	[Manufacturing date] [varchar](50) NULL,
	[Shelf life period in days] [varchar](50) NULL,
	[Expiration date] [varchar](50) NULL,
	[Physical inventory] [varchar](50) NULL,
	[Physical reserved] [varchar](50) NULL,
	[Available physical] [varchar](50) NULL,
	[Ordered] [varchar](50) NULL,
	[Ordered reserved] [varchar](50) NULL,
	[Total available] [varchar](50) NULL
) ON [PRIMARY]
GO
/****** Object:  Table [dbo].[Drug_Batch_Stock_COMBINED_D365_Expiry_order_sum_6mos]    Script Date: 30/07/2025 12:27:44 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[Drug_Batch_Stock_COMBINED_D365_Expiry_order_sum_6mos](
	[Drug_id] [varchar](50) NULL,
	[Stock] [float] NULL
) ON [PRIMARY]
GO
/****** Object:  Table [dbo].[DVReleasedProducts]    Script Date: 30/07/2025 12:27:44 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[DVReleasedProducts](
	[ItemNumber] [int] NULL,
	[PrimaryVendorAccountNumber] [varchar](255) NULL,
	[UnitCost] [float] NULL,
	[ProductName] [varchar](255) NULL,
	[PurchasePrice] [float] NULL,
	[SalesPrice] [float] NULL
) ON [PRIMARY]
GO
/****** Object:  Table [dbo].[DVReleasedProducts_transit]    Script Date: 30/07/2025 12:27:44 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[DVReleasedProducts_transit](
	[ItemNumber] [int] NULL,
	[PrimaryVendorAccountNumber] [varchar](255) NULL,
	[UnitCost] [float] NULL,
	[ProductName] [varchar](255) NULL,
	[PurchasePrice] [float] NULL,
	[SalesPrice] [float] NULL
) ON [PRIMARY]
GO
/****** Object:  Table [dbo].[DynamicsExport_638476272634989772_crm]    Script Date: 30/07/2025 12:27:44 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[DynamicsExport_638476272634989772_crm](
	[Integration log id] [varchar](50) NULL,
	[Order_id] [varchar](50) NULL,
	[Order_source] [varchar](50) NULL,
	[Branch_name] [varchar](50) NULL,
	[Branch_id] [varchar](50) NULL,
	[Agent_name] [varchar](50) NULL,
	[Status] [varchar](50) NULL,
	[With_insurance] [varchar](50) NULL,
	[Patient_name] [varchar](50) NULL,
	[Driver] [varchar](50) NULL,
	[Schedule_date] [varchar](50) NULL,
	[Payment_method] [varchar](50) NULL,
	[Reference_number] [varchar](50) NULL,
	[Sub_total] [varchar](50) NULL,
	[Delivery_charges] [varchar](50) NULL,
	[Discount] [varchar](50) NULL,
	[CRM total] [varchar](50) NULL,
	[Header status] [varchar](50) NULL,
	[Latest status] [varchar](50) NULL,
	[Header remarks] [varchar](254) NULL,
	[Sales order] [varchar](254) NULL,
	[parnter_name] [varchar](254) NULL,
	[additional_charges] [varchar](50) NULL,
	[Settled] [varchar](50) NULL,
	[Voucher] [varchar](50) NULL,
	[SKU] [varchar](50) NULL,
	[Name] [varchar](254) NULL,
	[Quantity] [varchar](50) NULL,
	[Price_without_vat] [varchar](50) NULL,
	[Vat_value] [varchar](50) NULL,
	[Price_with_vat] [varchar](50) NULL,
	[Line discount] [varchar](50) NULL,
	[Vat] [varchar](50) NULL,
	[Line number] [varchar](50) NULL,
	[Line status] [varchar](50) NULL,
	[Line remarks] [varchar](50) NULL,
	[Batch] [varchar](50) NULL,
	[Expiry] [varchar](50) NULL
) ON [PRIMARY]
GO
/****** Object:  Table [dbo].[Expiry_items_Upload2]    Script Date: 30/07/2025 12:27:44 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[Expiry_items_Upload2](
	[Item number] [varchar](50) NULL,
	[Product name] [varchar](254) NULL,
	[Consignment item] [varchar](50) NULL,
	[Bonus Item] [varchar](50) NULL,
	[Warehouse] [varchar](50) NULL,
	[Batch number] [varchar](50) NULL,
	[Location] [varchar](50) NULL,
	[Warehouse Name] [varchar](50) NULL,
	[Primary Vendor] [varchar](50) NULL,
	[Vendor Name] [varchar](254) NULL,
	[Batch disposition code] [varchar](50) NULL,
	[Batch disposition status] [varchar](50) NULL,
	[Manufacturing date] [varchar](50) NULL,
	[Shelf life period in days] [varchar](50) NULL,
	[Expiration date] [varchar](50) NULL,
	[Physical inventory] [varchar](50) NULL,
	[Physical reserved] [varchar](50) NULL,
	[Available physical] [varchar](50) NULL,
	[Ordered] [varchar](50) NULL,
	[Ordered reserved] [varchar](50) NULL,
	[Total available] [varchar](50) NULL
) ON [PRIMARY]
GO
/****** Object:  Table [dbo].[Export$]    Script Date: 30/07/2025 12:27:44 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[Export$](
	[Product Id] [nvarchar](255) NULL,
	[Product Name] [nvarchar](255) NULL,
	[Unit] [nvarchar](255) NULL,
	[Brand] [nvarchar](255) NULL,
	[Main Category] [nvarchar](255) NULL,
	[Sub Category] [nvarchar](255) NULL,
	[Category] [nvarchar](255) NULL,
	[Sub Category#1] [nvarchar](255) NULL,
	[Generic] [nvarchar](255) NULL,
	[Is Marina] [nvarchar](255) NULL,
	[Supplier Id] [nvarchar](255) NULL,
	[Supplier] [nvarchar](255) NULL,
	[Tax Group] [nvarchar](255) NULL,
	[unit cost] [float] NULL,
	[Sales Price] [float] NULL,
	[Aggrement_Cost] [float] NULL,
	[Retail Price] [float] NULL,
	[Hotel Price] [float] NULL,
	[Is Active] [nvarchar](255) NULL
) ON [PRIMARY]
GO
/****** Object:  Table [dbo].[fConsumption]    Script Date: 30/07/2025 12:27:44 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[fConsumption](
	[RequestedReceiptDate] [date] NULL,
	[ItemNumber] [varchar](250) NULL,
	[ShippingWarehouseId] [varchar](250) NULL,
	[SalesUnitSymbol] [varchar](250) NULL,
	[OrderedSalesQuantity] [float] NULL,
	[LineAmount] [decimal](18, 2) NULL,
	[LineDiscountAmount] [decimal](18, 2) NULL,
	[SalesOrderLineStatus] [nvarchar](50) NULL,
	[UpdateDate] [datetime] NULL
) ON [PRIMARY]
GO
/****** Object:  Table [dbo].[fConsumption_temp]    Script Date: 30/07/2025 12:27:44 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[fConsumption_temp](
	[RequestedReceiptDate] [date] NULL,
	[ItemNumber] [varchar](250) NULL,
	[ShippingWarehouseId] [varchar](250) NULL,
	[SalesUnitSymbol] [varchar](250) NULL,
	[OrderedSalesQuantity] [float] NULL,
	[LineAmount] [decimal](18, 2) NULL,
	[LineDiscountAmount] [decimal](18, 2) NULL,
	[SalesOrderLineStatus] [nvarchar](50) NULL,
	[UpdateDate] [datetime] NULL
) ON [PRIMARY]
GO
/****** Object:  Table [dbo].[fConsumption_transit]    Script Date: 30/07/2025 12:27:44 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[fConsumption_transit](
	[RequestedReceiptDate] [date] NULL,
	[ItemNumber] [varchar](250) NULL,
	[ShippingWarehouseId] [varchar](250) NULL,
	[SalesUnitSymbol] [varchar](250) NULL,
	[OrderedSalesQuantity] [float] NULL,
	[LineAmount] [decimal](18, 2) NULL,
	[LineDiscountAmount] [decimal](18, 2) NULL,
	[SalesOrderLineStatus] [nvarchar](50) NULL
) ON [PRIMARY]
GO
/****** Object:  Table [dbo].[FEB2024_MinMax_Order_Branch_Final]    Script Date: 30/07/2025 12:27:44 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[FEB2024_MinMax_Order_Branch_Final](
	[ItemNumber] [nvarchar](max) NULL,
	[ProductName] [nvarchar](max) NULL,
	[ProductGroupId] [nvarchar](max) NULL,
	[RetailProductCategoryname] [nvarchar](max) NULL,
	[SalesSalesTaxItemGroupCode] [nvarchar](max) NULL,
	[Drug_id] [varchar](50) NULL,
	[STORECODE] [varchar](50) NULL,
	[LocationID] [varchar](50) NULL,
	[ShortName] [varchar](50) NULL,
	[Min] [int] NULL,
	[Max] [int] NULL,
	[Cost] [varchar](50) NULL,
	[Price] [varchar](50) NULL,
	[Vendor] [varchar](50) NULL,
	[Stock] [float] NOT NULL,
	[Pending_Stock] [float] NOT NULL,
	[Order] [int] NULL,
	[CONS] [money] NOT NULL,
	[TR_Pending] [float] NOT NULL,
	[Unposted_Qty] [numeric](38, 2) NULL,
	[order_group] [nvarchar](max) NULL
) ON [PRIMARY] TEXTIMAGE_ON [PRIMARY]
GO
/****** Object:  Table [dbo].[FEB2024_MinMax_Order_Branch_Final_ALL_WH]    Script Date: 30/07/2025 12:27:44 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[FEB2024_MinMax_Order_Branch_Final_ALL_WH](
	[ItemNumber] [nvarchar](max) NULL,
	[ProductName] [nvarchar](max) NULL,
	[ProductGroupId] [nvarchar](max) NULL,
	[RetailProductCategoryname] [nvarchar](max) NULL,
	[SalesSalesTaxItemGroupCode] [nvarchar](max) NULL,
	[Drug_id] [varchar](50) NULL,
	[STORECODE] [varchar](50) NULL,
	[LocationID] [varchar](50) NULL,
	[ShortName] [varchar](50) NULL,
	[Min] [int] NULL,
	[Max] [int] NULL,
	[Cost] [varchar](50) NULL,
	[Price] [varchar](50) NULL,
	[Vendor] [varchar](50) NULL,
	[Stock] [float] NOT NULL,
	[Pending_Stock] [float] NOT NULL,
	[Order] [int] NULL,
	[CONS] [money] NOT NULL,
	[TR_Pending] [float] NOT NULL,
	[Unposted_Qty] [numeric](38, 2) NULL,
	[order_group] [nvarchar](max) NULL
) ON [PRIMARY] TEXTIMAGE_ON [PRIMARY]
GO
/****** Object:  Table [dbo].[FEB2024_MinMax_Order_Branch_Final_ALL_WH_DIVISION]    Script Date: 30/07/2025 12:27:44 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[FEB2024_MinMax_Order_Branch_Final_ALL_WH_DIVISION](
	[ItemNumber] [nvarchar](max) NULL,
	[ProductName] [nvarchar](max) NULL,
	[ProductGroupId] [nvarchar](max) NULL,
	[RetailProductCategoryname] [nvarchar](max) NULL,
	[SalesSalesTaxItemGroupCode] [nvarchar](max) NULL,
	[Drug_id] [varchar](50) NULL,
	[STORECODE] [varchar](50) NULL,
	[LocationID] [varchar](50) NULL,
	[ShortName] [varchar](50) NULL,
	[Min] [int] NULL,
	[Max] [int] NULL,
	[Cost] [varchar](50) NULL,
	[Price] [varchar](50) NULL,
	[Vendor] [varchar](50) NULL,
	[Stock] [float] NOT NULL,
	[Pending_Stock] [float] NOT NULL,
	[Order] [int] NULL,
	[CONS] [money] NOT NULL,
	[TR_Pending] [float] NOT NULL,
	[Unposted_Qty] [numeric](38, 2) NULL,
	[order_group] [nvarchar](max) NULL,
	[Hospital] [varchar](3) NOT NULL,
	[Retail] [varchar](3) NOT NULL,
	[800] [varchar](3) NOT NULL
) ON [PRIMARY] TEXTIMAGE_ON [PRIMARY]
GO
/****** Object:  Table [dbo].[FEB2024_MinMax_Order_Branch_Final_ALL_WH_MIN]    Script Date: 30/07/2025 12:27:44 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[FEB2024_MinMax_Order_Branch_Final_ALL_WH_MIN](
	[ItemNumber] [nvarchar](max) NULL,
	[ProductName] [nvarchar](max) NULL,
	[ProductGroupId] [nvarchar](max) NULL,
	[RetailProductCategoryname] [nvarchar](max) NULL,
	[SalesSalesTaxItemGroupCode] [nvarchar](max) NULL,
	[Drug_id] [varchar](50) NULL,
	[STORECODE] [varchar](50) NULL,
	[LocationID] [varchar](50) NULL,
	[ShortName] [varchar](50) NULL,
	[Min] [int] NULL,
	[Max] [int] NULL,
	[Cost] [varchar](50) NULL,
	[Price] [varchar](50) NULL,
	[Vendor] [varchar](50) NULL,
	[Stock] [float] NOT NULL,
	[Pending_Stock] [float] NOT NULL,
	[Order] [int] NULL,
	[CONS] [money] NOT NULL,
	[TR_Pending] [float] NOT NULL,
	[Unposted_Qty] [numeric](38, 2) NULL,
	[order_group] [nvarchar](max) NULL
) ON [PRIMARY] TEXTIMAGE_ON [PRIMARY]
GO
/****** Object:  Table [dbo].[FEB2024_MinMax_Order_Branch_Final_for_DynamicsUpload]    Script Date: 30/07/2025 12:27:44 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[FEB2024_MinMax_Order_Branch_Final_for_DynamicsUpload](
	[ItemNumber] [nvarchar](max) NULL,
	[ProductName] [nvarchar](max) NULL,
	[StoreCode] [varchar](50) NULL,
	[Actual_Order] [int] NULL,
	[To_Order] [int] NULL,
	[Bonus] [int] NULL,
	[BonusScheme] [varchar](50) NULL,
	[Vendor] [varchar](14) NOT NULL,
	[ref] [nvarchar](max) NULL
) ON [PRIMARY] TEXTIMAGE_ON [PRIMARY]
GO
/****** Object:  Table [dbo].[FEB2024_MinMax_Order_Branch_Final_for_DynamicsUpload_Final]    Script Date: 30/07/2025 12:27:44 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[FEB2024_MinMax_Order_Branch_Final_for_DynamicsUpload_Final](
	[Purchase order] [varchar](16) NOT NULL,
	[Line number] [int] NOT NULL,
	[Item number] [nvarchar](max) NULL,
	[Quantity] [int] NULL,
	[Unit] [varchar](4) NOT NULL,
	[Unit price] [numeric](5, 2) NOT NULL,
	[FOC] [varchar](3) NOT NULL,
	[External item number] [varchar](1) NOT NULL,
	[Vendor] [varchar](14) NOT NULL,
	[ref] [nvarchar](max) NULL,
	[StoreCode] [nchar](10) NULL
) ON [PRIMARY] TEXTIMAGE_ON [PRIMARY]
GO
/****** Object:  Table [dbo].[FEB2024_MinMax_RE_Order_Branch_Final]    Script Date: 30/07/2025 12:27:44 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[FEB2024_MinMax_RE_Order_Branch_Final](
	[ItemNumber] [nvarchar](max) NULL,
	[ProductName] [nvarchar](max) NULL,
	[ProductGroupId] [nvarchar](max) NULL,
	[RetailProductCategoryname] [nvarchar](max) NULL,
	[SalesSalesTaxItemGroupCode] [nvarchar](max) NULL,
	[Drug_id] [varchar](50) NULL,
	[STORECODE] [varchar](50) NULL,
	[LocationID] [varchar](50) NULL,
	[ShortName] [varchar](50) NULL,
	[Min] [int] NULL,
	[Max] [int] NULL,
	[Cost] [varchar](50) NULL,
	[Price] [varchar](50) NULL,
	[Vendor] [varchar](50) NULL,
	[Stock] [float] NOT NULL,
	[Pending_Stock] [float] NOT NULL,
	[Order] [int] NULL,
	[CONS] [money] NOT NULL,
	[turn] [varchar](50) NULL,
	[Store_Stock] [float] NOT NULL,
	[Category] [varchar](50) NULL,
	[Ordered] [float] NOT NULL,
	[Unposted_Qty] [numeric](38, 2) NULL,
	[Qty_Unposted] [decimal](38, 2) NOT NULL,
	[Stock_after_Unposted] [float] NOT NULL
) ON [PRIMARY] TEXTIMAGE_ON [PRIMARY]
GO
/****** Object:  Table [dbo].[FEB2024_MinMax_RE_Order_Branch_Final_800]    Script Date: 30/07/2025 12:27:44 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[FEB2024_MinMax_RE_Order_Branch_Final_800](
	[ItemNumber] [nvarchar](max) NULL,
	[ProductName] [nvarchar](max) NULL,
	[ProductGroupId] [nvarchar](max) NULL,
	[RetailProductCategoryname] [nvarchar](max) NULL,
	[SalesSalesTaxItemGroupCode] [nvarchar](max) NULL,
	[Drug_id] [varchar](50) NULL,
	[STORECODE] [varchar](50) NULL,
	[LocationID] [varchar](50) NULL,
	[ShortName] [varchar](50) NULL,
	[Min] [int] NULL,
	[Max] [int] NULL,
	[Cost] [varchar](50) NULL,
	[Price] [varchar](50) NULL,
	[Vendor] [varchar](50) NULL,
	[Stock] [float] NOT NULL,
	[Pending_Stock] [float] NOT NULL,
	[Order] [int] NULL,
	[CONS] [money] NOT NULL,
	[turn] [varchar](50) NULL,
	[Store_Stock] [float] NOT NULL,
	[Category] [varchar](50) NULL,
	[Ordered] [float] NOT NULL,
	[Unposted_Qty] [numeric](38, 2) NULL,
	[Qty_Unposted] [decimal](38, 2) NOT NULL,
	[Stock_after_Unposted] [float] NOT NULL
) ON [PRIMARY] TEXTIMAGE_ON [PRIMARY]
GO
/****** Object:  Table [dbo].[FEB2024_MinMax_RE_Order_Branch_Final_max]    Script Date: 30/07/2025 12:27:44 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[FEB2024_MinMax_RE_Order_Branch_Final_max](
	[ItemNumber] [nvarchar](max) NULL,
	[ProductName] [nvarchar](max) NULL,
	[ProductGroupId] [nvarchar](max) NULL,
	[RetailProductCategoryname] [nvarchar](max) NULL,
	[SalesSalesTaxItemGroupCode] [nvarchar](max) NULL,
	[Drug_id] [varchar](50) NULL,
	[STORECODE] [varchar](50) NULL,
	[LocationID] [varchar](50) NULL,
	[ShortName] [varchar](50) NULL,
	[Min] [int] NULL,
	[Max] [int] NULL,
	[Cost] [varchar](50) NULL,
	[Price] [varchar](50) NULL,
	[Vendor] [varchar](50) NULL,
	[Stock] [float] NOT NULL,
	[Pending_Stock] [float] NOT NULL,
	[Order] [int] NULL,
	[CONS] [money] NOT NULL,
	[turn] [varchar](50) NULL,
	[Store_Stock] [float] NOT NULL,
	[Category] [varchar](50) NULL,
	[Ordered] [float] NOT NULL,
	[Unposted_Qty] [numeric](38, 2) NULL,
	[Qty_Unposted] [decimal](38, 2) NOT NULL,
	[Stock_after_Unposted] [float] NOT NULL
) ON [PRIMARY] TEXTIMAGE_ON [PRIMARY]
GO
/****** Object:  Table [dbo].[fInventory]    Script Date: 30/07/2025 12:27:44 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[fInventory](
	[ItemNumber] [varchar](255) NULL,
	[WarehouseId] [varchar](255) NULL,
	[AvailPhysical] [float] NULL
) ON [PRIMARY]
GO
/****** Object:  Table [dbo].[GeneralJournalAccountEntryBiEntities]    Script Date: 30/07/2025 12:27:44 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[GeneralJournalAccountEntryBiEntities](
	[SourceKey] [bigint] NULL,
	[PostingType] [nvarchar](max) NULL,
	[AccountingCurrencyAmount] [float] NULL,
	[SysRecVersion] [bigint] NULL,
	[CreatedByTransactionId] [bigint] NULL,
	[IsCredit] [nvarchar](max) NULL,
	[FinTag] [bigint] NULL,
	[GeneralJournalEntry] [bigint] NULL,
	[ReasonRef] [bigint] NULL,
	[AssetLeaseTransactionType] [nvarchar](max) NULL,
	[AssetLeasePostingTypes] [nvarchar](max) NULL,
	[TransactionCurrencyCode] [nvarchar](max) NULL,
	[LedgerAccount] [nvarchar](max) NULL,
	[PaymentReference] [nvarchar](max) NULL,
	[ReportingCurrencyAmount] [float] NULL,
	[Text] [nvarchar](max) NULL,
	[TransactionCurrencyAmount] [float] NULL,
	[ProjTableDataAreaId] [nvarchar](max) NULL,
	[ProjId_SA] [nvarchar](max) NULL,
	[IsCorrection] [nvarchar](max) NULL,
	[HistoricalExchangeRateDate] [datetime2](0) NULL,
	[AllocationLevel] [bigint] NULL,
	[Quantity] [float] NULL,
	[OriginalAccountEntry] [bigint] NULL,
	[MainAccount] [bigint] NULL,
	[LedgerDimensionValuesJson] [nvarchar](max) NULL
) ON [PRIMARY] TEXTIMAGE_ON [PRIMARY]
GO
/****** Object:  Table [dbo].[HSInventSums_1303_morning]    Script Date: 30/07/2025 12:27:44 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[HSInventSums_1303_morning](
	[dataAreaId] [nvarchar](max) NULL,
	[ItemId] [nvarchar](max) NULL,
	[InventDimId] [nvarchar](max) NULL,
	[QuotationReceipt] [float] NULL,
	[PostedQty] [float] NULL,
	[AvailPhysical] [float] NULL,
	[InventDim_InventSiteId] [nvarchar](max) NULL,
	[LastUpdDatePhysical] [datetime2](0) NULL,
	[ReservOrdered] [float] NULL,
	[Closed] [nvarchar](max) NULL,
	[InventDim_wMSLocationId] [nvarchar](max) NULL,
	[Ordered] [float] NULL,
	[InventDim_inventDimId] [nvarchar](max) NULL,
	[LastUpdDateExpected] [datetime2](0) NULL,
	[InventDim_InventLocationId] [nvarchar](max) NULL,
	[Received] [float] NULL,
	[ReservPhysical] [float] NULL,
	[IsExcludedFromInventoryValue] [nvarchar](max) NULL,
	[Picked] [float] NULL,
	[QuotationIssue] [float] NULL,
	[Deducted] [float] NULL,
	[OnOrder] [float] NULL,
	[PhysicalInvent] [float] NULL,
	[PhysicalValue] [float] NULL,
	[AvailOrdered] [float] NULL,
	[ClosedQty] [nvarchar](max) NULL,
	[PostedValue] [float] NULL,
	[Registered] [float] NULL,
	[Arrived] [float] NULL,
	[inventBatchId] [nvarchar](max) NULL
) ON [PRIMARY] TEXTIMAGE_ON [PRIMARY]
GO
/****** Object:  Table [dbo].[HSInventSums_97]    Script Date: 30/07/2025 12:27:44 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[HSInventSums_97](
	[ItemId] [int] NULL,
	[InventDim_InventSiteId] [varchar](255) NULL,
	[InventDim_wMSLocationId] [varchar](255) NULL,
	[inventBatchId] [varchar](255) NULL,
	[AvailPhysical] [float] NULL,
	[Ordered] [float] NULL,
	[LastUpdate] [datetime] NULL
) ON [PRIMARY]
GO
/****** Object:  Table [dbo].[HSInventSums_final_transit]    Script Date: 30/07/2025 12:27:44 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[HSInventSums_final_transit](
	[ItemId] [int] NULL,
	[InventDim_InventSiteId] [varchar](255) NULL,
	[InventDim_wMSLocationId] [varchar](255) NULL,
	[inventBatchId] [varchar](255) NULL,
	[AvailPhysical] [float] NULL,
	[Ordered] [float] NULL,
	[UpdateTime] [datetime] NULL
) ON [PRIMARY]
GO
/****** Object:  Table [dbo].[HSInventSums_old]    Script Date: 30/07/2025 12:27:44 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[HSInventSums_old](
	[dataAreaId] [nvarchar](max) NULL,
	[ItemId] [nvarchar](max) NULL,
	[InventDimId] [nvarchar](max) NULL,
	[QuotationReceipt] [float] NULL,
	[PostedQty] [float] NULL,
	[AvailPhysical] [float] NULL,
	[InventDim_InventSiteId] [nvarchar](max) NULL,
	[LastUpdDatePhysical] [datetime2](0) NULL,
	[ReservOrdered] [float] NULL,
	[Closed] [nvarchar](max) NULL,
	[InventDim_wMSLocationId] [nvarchar](max) NULL,
	[Ordered] [float] NULL,
	[InventDim_inventDimId] [nvarchar](max) NULL,
	[LastUpdDateExpected] [datetime2](0) NULL,
	[InventDim_InventLocationId] [nvarchar](max) NULL,
	[Received] [float] NULL,
	[ReservPhysical] [float] NULL,
	[IsExcludedFromInventoryValue] [nvarchar](max) NULL,
	[Picked] [float] NULL,
	[QuotationIssue] [float] NULL,
	[Deducted] [float] NULL,
	[OnOrder] [float] NULL,
	[PhysicalInvent] [float] NULL,
	[PhysicalValue] [float] NULL,
	[AvailOrdered] [float] NULL,
	[ClosedQty] [nvarchar](max) NULL,
	[PostedValue] [float] NULL,
	[Registered] [float] NULL,
	[Arrived] [float] NULL,
	[inventBatchId] [nvarchar](max) NULL
) ON [PRIMARY] TEXTIMAGE_ON [PRIMARY]
GO
/****** Object:  Table [dbo].[HSInventSums_test]    Script Date: 30/07/2025 12:27:44 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[HSInventSums_test](
	[ItemId] [nvarchar](max) NULL,
	[InventDim_InventSiteId] [nvarchar](max) NULL,
	[AvailPhysical] [float] NULL
) ON [PRIMARY] TEXTIMAGE_ON [PRIMARY]
GO
/****** Object:  Table [dbo].[HSInventSums_transit]    Script Date: 30/07/2025 12:27:44 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[HSInventSums_transit](
	[ItemId] [int] NULL,
	[InventDim_InventSiteId] [varchar](255) NULL,
	[InventDim_wMSLocationId] [varchar](255) NULL,
	[inventBatchId] [varchar](255) NULL,
	[AvailPhysical] [float] NULL,
	[Ordered] [float] NULL
) ON [PRIMARY]
GO
/****** Object:  Table [dbo].[HSInventSums1]    Script Date: 30/07/2025 12:27:44 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[HSInventSums1](
	[ItemId] [nvarchar](max) NULL,
	[PostedQty] [float] NULL,
	[AvailPhysical] [float] NULL,
	[InventDim_InventSiteId] [nvarchar](max) NULL,
	[LastUpdDatePhysical] [datetime2](0) NULL,
	[Closed] [nvarchar](max) NULL,
	[Ordered] [float] NULL,
	[LastUpdDateExpected] [datetime2](0) NULL,
	[InventDim_InventLocationId] [nvarchar](max) NULL,
	[Deducted] [float] NULL,
	[OnOrder] [float] NULL,
	[inventBatchId] [nvarchar](max) NULL,
	[InventDim_wMSLocationId] [nvarchar](max) NULL
) ON [PRIMARY] TEXTIMAGE_ON [PRIMARY]
GO
/****** Object:  Table [dbo].[HSSalesOrderHeaders]    Script Date: 30/07/2025 12:27:44 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[HSSalesOrderHeaders](
	[dataAreaId] [nvarchar](max) NULL,
	[IntegrationLogId] [nvarchar](max) NULL,
	[Order_id] [nvarchar](max) NULL,
	[Schedule_timeT] [bigint] NULL,
	[Agent_name] [nvarchar](max) NULL,
	[First_Name] [nvarchar](max) NULL,
	[Approval_code] [nvarchar](max) NULL,
	[Discount] [float] NULL,
	[Status] [nvarchar](max) NULL,
	[Branch_id] [nvarchar](max) NULL,
	[Total_order_time] [nvarchar](max) NULL,
	[Street] [nvarchar](max) NULL,
	[Sub_total] [float] NULL,
	[Schedule_date] [datetime2](0) NULL,
	[Discount_reason] [nvarchar](max) NULL,
	[Apartment_number] [nvarchar](max) NULL,
	[Patient_name] [nvarchar](max) NULL,
	[Total_task_time] [nvarchar](max) NULL,
	[Multi_delivery] [bigint] NULL,
	[Full_address] [nvarchar](max) NULL,
	[With_insurance] [nvarchar](max) NULL,
	[Reference_number] [nvarchar](max) NULL,
	[Email] [nvarchar](max) NULL,
	[Schedule] [nvarchar](max) NULL,
	[Prepared_by] [nvarchar](max) NULL,
	[Order_source] [nvarchar](max) NULL,
	[parnter_name] [nvarchar](max) NULL,
	[Total] [float] NULL,
	[Comments] [nvarchar](max) NULL,
	[Schedule_time] [nvarchar](max) NULL,
	[Area_name] [nvarchar](max) NULL,
	[additional_charges] [float] NULL,
	[Branch_name] [nvarchar](max) NULL,
	[Claim_form_no] [nvarchar](max) NULL,
	[Last_Name] [nvarchar](max) NULL,
	[Delivery_charges] [float] NULL,
	[Payment_method] [nvarchar](max) NULL,
	[Mobile] [nvarchar](max) NULL,
	[Driver] [nvarchar](max) NULL,
	[Clinic_Code] [nvarchar](max) NULL,
	[Clinic_Name] [nvarchar](max) NULL,
	[Insurance_provider] [nvarchar](max) NULL,
	[IntegrationStatus] [bigint] NULL,
	[Insurance_card_no] [nvarchar](max) NULL
) ON [PRIMARY] TEXTIMAGE_ON [PRIMARY]
GO
/****** Object:  Table [dbo].[HSSalesOrderLines]    Script Date: 30/07/2025 12:27:44 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[HSSalesOrderLines](
	[dataAreaId] [nvarchar](max) NULL,
	[IntegrationLogId] [nvarchar](max) NULL,
	[Order_id] [nvarchar](max) NULL,
	[LineNum] [float] NULL,
	[Expiry] [datetime2](0) NULL,
	[Vat] [float] NULL,
	[Vat_value] [float] NULL,
	[Batch_number] [nvarchar](max) NULL,
	[Price_without_vat] [float] NULL,
	[Price_with_vat] [float] NULL,
	[Discount] [float] NULL,
	[IntegrationStatus] [bigint] NULL,
	[Name] [nvarchar](max) NULL,
	[Quantity] [float] NULL,
	[Discount_reason] [nvarchar](max) NULL,
	[SKU] [nvarchar](max) NULL
) ON [PRIMARY] TEXTIMAGE_ON [PRIMARY]
GO
/****** Object:  Table [dbo].[HSSalesOrderTimestamps]    Script Date: 30/07/2025 12:27:44 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[HSSalesOrderTimestamps](
	[dataAreaId] [nvarchar](max) NULL,
	[IntegrationLogId] [nvarchar](max) NULL,
	[Order_id] [nvarchar](max) NULL,
	[Event] [nvarchar](max) NULL,
	[Time_stamp] [nvarchar](max) NULL,
	[IntegrationStatus] [bigint] NULL
) ON [PRIMARY] TEXTIMAGE_ON [PRIMARY]
GO
/****** Object:  Table [dbo].[Inventory_Sum]    Script Date: 30/07/2025 12:27:44 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[Inventory_Sum](
	[ItemId] [int] NULL,
	[InventDim_InventLocationId] [varchar](255) NULL,
	[Stock] [float] NULL
) ON [PRIMARY]
GO
/****** Object:  Table [dbo].[InventoryOnHandForAI]    Script Date: 30/07/2025 12:27:44 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[InventoryOnHandForAI](
	[dataAreaId] [nvarchar](max) NULL,
	[ItemNumber] [nvarchar](max) NULL,
	[SiteId] [nvarchar](max) NULL,
	[WarehouseId] [nvarchar](max) NULL,
	[ProductConfigurationId] [nvarchar](max) NULL,
	[ProductColorId] [nvarchar](max) NULL,
	[ProductSizeId] [nvarchar](max) NULL,
	[ProductStyleId] [nvarchar](max) NULL,
	[InventoryStatus] [nvarchar](max) NULL,
	[IsWarehouseItem] [nvarchar](max) NULL,
	[AvailPhysical] [float] NULL,
	[CalculatedAvailablePhysical] [float] NULL,
	[dataAreaId.1] [nvarchar](max) NULL,
	[WarehouseId.1] [nvarchar](max) NULL,
	[Name] [nvarchar](max) NULL,
	[SiteId.1] [nvarchar](max) NULL
) ON [PRIMARY] TEXTIMAGE_ON [PRIMARY]
GO
/****** Object:  Table [dbo].[InventoryOnHandForAI2]    Script Date: 30/07/2025 12:27:44 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[InventoryOnHandForAI2](
	[dataAreaId] [nvarchar](max) NULL,
	[ItemNumber] [nvarchar](max) NULL,
	[SiteId] [nvarchar](max) NULL,
	[WarehouseId] [nvarchar](max) NULL,
	[ProductConfigurationId] [nvarchar](max) NULL,
	[ProductColorId] [nvarchar](max) NULL,
	[ProductSizeId] [nvarchar](max) NULL,
	[ProductStyleId] [nvarchar](max) NULL,
	[InventoryStatus] [nvarchar](max) NULL,
	[IsWarehouseItem] [nvarchar](max) NULL,
	[AvailPhysical] [float] NULL,
	[CalculatedAvailablePhysical] [float] NULL
) ON [PRIMARY] TEXTIMAGE_ON [PRIMARY]
GO
/****** Object:  Table [dbo].[InventoryTransferJournalEntries]    Script Date: 30/07/2025 12:27:44 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[InventoryTransferJournalEntries](
	[dataAreaId] [nvarchar](max) NULL,
	[JournalNumber] [nvarchar](max) NULL,
	[LineNumber] [float] NULL,
	[SourceInventorySiteId] [nvarchar](max) NULL,
	[SourceProductVersionId] [nvarchar](max) NULL,
	[SourceProductConfigurationId] [nvarchar](max) NULL,
	[DestinationInventoryOwnerId] [nvarchar](max) NULL,
	[SourceItemSerialNumber] [nvarchar](max) NULL,
	[DestinationProductConfigurationId] [nvarchar](max) NULL,
	[DestinationInventoryStatusId] [nvarchar](max) NULL,
	[DestinationProductSizeId] [nvarchar](max) NULL,
	[ItemNumber] [nvarchar](max) NULL,
	[DestinationLicensePlateNumber] [nvarchar](max) NULL,
	[SourceLicensePlateNumber] [nvarchar](max) NULL,
	[InventoryQuantity] [float] NULL,
	[SourceInventoryProfileId] [nvarchar](max) NULL,
	[DestinationItemSerialNumber] [nvarchar](max) NULL,
	[DestinationInventorySiteId] [nvarchar](max) NULL,
	[UnitCostQuantity] [float] NULL,
	[SourceInventoryStatusId] [nvarchar](max) NULL,
	[SourceProductSizeId] [nvarchar](max) NULL,
	[DestinationProductVersionId] [nvarchar](max) NULL,
	[DestinationWarehouseId] [nvarchar](max) NULL,
	[SourceProductColorId] [nvarchar](max) NULL,
	[SourceItemBatchNumber] [nvarchar](max) NULL,
	[TransactionDate] [datetime2](0) NULL,
	[DestinationProductStyleId] [nvarchar](max) NULL,
	[DestinationWarehouseLocationId] [nvarchar](max) NULL,
	[SourceInventoryGtdId] [nvarchar](max) NULL,
	[SourceProductStyleId] [nvarchar](max) NULL,
	[DefaultLedgerDimensionDisplayValue] [nvarchar](max) NULL,
	[DestinationProductColorId] [nvarchar](max) NULL,
	[CatchWeightQuantity] [float] NULL,
	[DestinationInventoryProfileId] [nvarchar](max) NULL,
	[JournalNameId] [nvarchar](max) NULL,
	[SourceInventoryOwnerId] [nvarchar](max) NULL,
	[SourceWarehouseLocationId] [nvarchar](max) NULL,
	[DestinationItemBatchNumber] [nvarchar](max) NULL,
	[SourceWarehouseId] [nvarchar](max) NULL,
	[DestinationInventoryGtdId] [nvarchar](max) NULL
) ON [PRIMARY] TEXTIMAGE_ON [PRIMARY]
GO
/****** Object:  Table [dbo].[InventoryTransferJournalHeaders]    Script Date: 30/07/2025 12:27:44 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[InventoryTransferJournalHeaders](
	[dataAreaId] [nvarchar](max) NULL,
	[JournalNumber] [nvarchar](max) NULL,
	[IsPosted] [nvarchar](max) NULL,
	[Description] [nvarchar](max) NULL,
	[DefaultWarehouseId] [nvarchar](max) NULL,
	[ReservationMode] [nvarchar](max) NULL,
	[PostingDetailLevel] [nvarchar](max) NULL,
	[DefaultInventorySiteId] [nvarchar](max) NULL,
	[JournalNameId] [nvarchar](max) NULL,
	[VoucherNumberSelectionRule] [nvarchar](max) NULL,
	[PostedDateTime] [datetime2](0) NULL,
	[VoucherNumberAllocationRule] [nvarchar](max) NULL,
	[VoucherNumberSequenceCode] [nvarchar](max) NULL,
	[AreLinesDeletedAfterPosting] [nvarchar](max) NULL,
	[PostedUserId] [nvarchar](max) NULL
) ON [PRIMARY] TEXTIMAGE_ON [PRIMARY]
GO
/****** Object:  Table [dbo].[InventTransferTableBiEntities]    Script Date: 30/07/2025 12:27:44 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[InventTransferTableBiEntities](
	[dataAreaId] [nvarchar](max) NULL,
	[TransferId] [nvarchar](max) NULL,
	[ATPInclPlannedOrders] [bit] NULL,
	[CargoDescription_RU] [nvarchar](max) NULL,
	[ToContactPerson] [bigint] NULL,
	[RetailReplenishRefRecId] [bigint] NULL,
	[TransportInvoiceType_RU] [nvarchar](max) NULL,
	[Listcode] [nvarchar](max) NULL,
	[ATPApplyDemandTimeFence] [bigint] NULL,
	[ATPTimeFence] [bigint] NULL,
	[SysRecVersion] [bigint] NULL,
	[ReasonTableRef] [bigint] NULL,
	[PriceType_IN] [nvarchar](max) NULL,
	[InventProfileIdTo_RU] [nvarchar](max) NULL,
	[TransportationPayerType_RU] [nvarchar](max) NULL,
	[PriceGroupId_RU] [nvarchar](max) NULL,
	[DeliveryDate_RU] [datetime2](0) NULL,
	[ATPApplySupplyTimeFence] [bigint] NULL,
	[DeliveryDateControlType] [nvarchar](max) NULL,
	[CarrierCode_RU] [nvarchar](max) NULL,
	[FreightZoneId] [nvarchar](max) NULL,
	[DlvTermId] [nvarchar](max) NULL,
	[CFDICartaPorteEnabled_MX] [nvarchar](max) NULL,
	[TransferStatus] [nvarchar](max) NULL,
	[InventProfileType_RU] [nvarchar](max) NULL,
	[CreatedOn] [datetime2](0) NULL,
	[Port] [nvarchar](max) NULL,
	[FromAddressName] [nvarchar](max) NULL,
	[InventProfileUseRelated_RU] [nvarchar](max) NULL,
	[UnladingPostalAddress_RU] [bigint] NULL,
	[TransactionCode] [nvarchar](max) NULL,
	[TransferType_IN] [nvarchar](max) NULL,
	[LicenseCardRegNum_RU] [nvarchar](max) NULL,
	[TransportationType_RU] [nvarchar](max) NULL,
	[TransportationPayer_RU] [nvarchar](max) NULL,
	[SysDataAreaId] [nvarchar](max) NULL,
	[DlvModeId] [nvarchar](max) NULL,
	[FreightSlipType] [nvarchar](max) NULL,
	[InventLocationIdTo] [nvarchar](max) NULL,
	[LicenseCardSeries_RU] [nvarchar](max) NULL,
	[Transport] [nvarchar](max) NULL,
	[LicenseCardType_RU] [nvarchar](max) NULL,
	[ATPBackwardSupplyTimeFence] [bigint] NULL,
	[SourceKey] [bigint] NULL,
	[ToPostalAddress] [bigint] NULL,
	[TrPackingSlipAutoNumbering_LT] [nvarchar](max) NULL,
	[Driver_RU] [nvarchar](max) NULL,
	[WaybillNum_RU] [nvarchar](max) NULL,
	[DriverName_RU] [nvarchar](max) NULL,
	[RetailRetailStatusType] [nvarchar](max) NULL,
	[FromPostalAddress] [bigint] NULL,
	[AutoReservation] [nvarchar](max) NULL,
	[ATPBackwardDemandTimeFence] [bigint] NULL,
	[PartyAgreementHeaderExt_RU] [bigint] NULL,
	[StockTransferCostPriceHandlingImprovement_IN] [nvarchar](max) NULL,
	[StatProcId] [nvarchar](max) NULL,
	[ToAddressName] [nvarchar](max) NULL,
	[CurrencyCode_RU] [nvarchar](max) NULL,
	[LadingPostalAddress_RU] [bigint] NULL,
	[RetailReplenishRefTableId] [bigint] NULL,
	[IntrastatFulfillmentDate_HU] [datetime2](0) NULL,
	[FromContactPerson] [bigint] NULL,
	[CarrierType_RU] [nvarchar](max) NULL,
	[CargoPacking_RU] [nvarchar](max) NULL,
	[InventLocationIdTransit] [nvarchar](max) NULL,
	[CFDIEnabled_MX] [nvarchar](max) NULL,
	[IntrastatSpecMove_CZ] [nvarchar](max) NULL,
	[DriverContact_RU] [nvarchar](max) NULL,
	[InventLocationIdFrom] [nvarchar](max) NULL,
	[ShipDate] [datetime2](0) NULL,
	[VehicleModel_RU] [nvarchar](max) NULL,
	[VehiclePlateNum_RU] [nvarchar](max) NULL,
	[Exempt_IN] [nvarchar](max) NULL,
	[InventProfileId_RU] [nvarchar](max) NULL,
	[LicenseCardNum_RU] [nvarchar](max) NULL,
	[PartyAccountNum_RU] [nvarchar](max) NULL,
	[PdsOverrideFEFO] [nvarchar](max) NULL,
	[DrivingLicenseNum_RU] [nvarchar](max) NULL,
	[ReceiveDate] [datetime2](0) NULL,
	[TransferType_RU] [nvarchar](max) NULL,
	[TransportationDocument] [bigint] NULL
) ON [PRIMARY] TEXTIMAGE_ON [PRIMARY]
GO
/****** Object:  Table [dbo].[ItemBatches]    Script Date: 30/07/2025 12:27:44 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[ItemBatches](
	[ItemNumber] [int] NULL,
	[BatchNumber] [varchar](255) NULL,
	[VendorBatchDate] [varchar](255) NULL,
	[BatchExpirationDate] [varchar](255) NULL,
	[ManufacturingDate] [varchar](255) NULL,
	[VendorExpirationDate] [varchar](255) NULL,
	[SAPBarcode] [varchar](255) NULL,
	[BatchIdSeq] [varchar](255) NULL
) ON [PRIMARY]
GO
/****** Object:  Table [dbo].[LedgerJournalHeaders]    Script Date: 30/07/2025 12:27:44 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[LedgerJournalHeaders](
	[dataAreaId] [nvarchar](max) NULL,
	[JournalBatchNumber] [nvarchar](max) NULL,
	[AccountingCurrency] [nvarchar](max) NULL,
	[JournalName] [nvarchar](max) NULL,
	[IntegrationKey] [nvarchar](max) NULL,
	[Description] [nvarchar](max) NULL,
	[PostingLayer] [nvarchar](max) NULL,
	[IsPosted] [nvarchar](max) NULL,
	[JournalTotalCredit] [float] NULL,
	[JournalTotalDebit] [float] NULL
) ON [PRIMARY] TEXTIMAGE_ON [PRIMARY]
GO
/****** Object:  Table [dbo].[LedgerJournalHeadersCDS]    Script Date: 30/07/2025 12:27:44 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[LedgerJournalHeadersCDS](
	[dataAreaId] [nvarchar](max) NULL,
	[IntegrationComputedKey] [nvarchar](max) NULL,
	[JournalBatchNumber] [nvarchar](max) NULL,
	[JournalName] [nvarchar](max) NULL,
	[IntegrationKey] [nvarchar](max) NULL,
	[Description] [nvarchar](max) NULL,
	[PostingLayer] [nvarchar](max) NULL,
	[IsPosted] [nvarchar](max) NULL,
	[JournalTotalCredit] [float] NULL,
	[JournalTotalDebit] [float] NULL
) ON [PRIMARY] TEXTIMAGE_ON [PRIMARY]
GO
/****** Object:  Table [dbo].[LedgerJournalLines (2)]    Script Date: 30/07/2025 12:27:44 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[LedgerJournalLines (2)](
	[dataAreaId] [nvarchar](max) NULL,
	[JournalBatchNumber] [nvarchar](max) NULL,
	[LineNumber] [float] NULL,
	[ReverseEntry] [nvarchar](max) NULL,
	[ItemSalesTaxGroup] [nvarchar](max) NULL,
	[CashDiscountDate] [datetime2](0) NULL,
	[Voucher] [nvarchar](max) NULL,
	[Text] [nvarchar](max) NULL,
	[OffsetAccountType] [nvarchar](max) NULL,
	[IsWithholdingCalculationEnabled] [nvarchar](max) NULL,
	[ReverseDate] [datetime2](0) NULL,
	[TransDate] [datetime2](0) NULL,
	[DefaultDimensionDisplayValue] [nvarchar](max) NULL,
	[PaymentReference] [nvarchar](max) NULL,
	[Document] [nvarchar](max) NULL,
	[CashDiscountAmount] [float] NULL,
	[ExchRate] [float] NULL,
	[ChineseVoucherType] [nvarchar](max) NULL,
	[DebitAmount] [float] NULL,
	[SalesTaxCode] [nvarchar](max) NULL,
	[DocumentDate] [datetime2](0) NULL,
	[OffsetAccountDisplayValue] [nvarchar](max) NULL,
	[AccountDisplayValue] [nvarchar](max) NULL,
	[CashDiscount] [nvarchar](max) NULL,
	[OffsetDefaultDimensionDisplayValue] [nvarchar](max) NULL,
	[OffsetFinTagDisplayValue] [nvarchar](max) NULL,
	[SalesTaxGroup] [nvarchar](max) NULL,
	[AccountType] [nvarchar](max) NULL,
	[Invoice] [nvarchar](max) NULL,
	[DueDate] [datetime2](0) NULL,
	[ReportingCurrencyExchRate] [float] NULL,
	[FinTagDisplayValue] [nvarchar](max) NULL,
	[PaymentMethod] [nvarchar](max) NULL,
	[PaymentId] [nvarchar](max) NULL,
	[PostingProfile] [nvarchar](max) NULL,
	[ExchRateSecond] [float] NULL,
	[CreditAmount] [float] NULL,
	[OverrideSalesTax] [nvarchar](max) NULL,
	[OffsetCompany] [nvarchar](max) NULL,
	[Quantity] [float] NULL,
	[ItemWithholdingTaxGroupCode] [nvarchar](max) NULL,
	[TaxExemptNumber] [nvarchar](max) NULL,
	[ReportingCurrencyExchRateSecondary] [float] NULL,
	[CurrencyCode] [nvarchar](max) NULL,
	[Company] [nvarchar](max) NULL,
	[ChineseVoucher] [nvarchar](max) NULL,
	[DiscountPercentage] [float] NULL,
	[OffsetText] [nvarchar](max) NULL
) ON [PRIMARY] TEXTIMAGE_ON [PRIMARY]
GO
/****** Object:  Table [dbo].[LedgerJournalTableBiEntities]    Script Date: 30/07/2025 12:27:44 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[LedgerJournalTableBiEntities](
	[dataAreaId] [nvarchar](max) NULL,
	[JournalNum] [nvarchar](max) NULL,
	[ReverseEntry] [nvarchar](max) NULL,
	[PostedDateTime] [datetime2](0) NULL,
	[SimulationPosted_IT] [nvarchar](max) NULL,
	[JournalName] [nvarchar](max) NULL,
	[OffsetAccountType] [nvarchar](max) NULL,
	[BankRemittanceType] [nvarchar](max) NULL,
	[ReverseDate] [datetime2](0) NULL,
	[RetailStatementId] [nvarchar](max) NULL,
	[JournalType] [nvarchar](max) NULL,
	[JournalBalance] [float] NULL,
	[VoucherAllocatedAtPosting] [nvarchar](max) NULL,
	[EUROTriangulation] [nvarchar](max) NULL,
	[FinTag] [bigint] NULL,
	[IsLedgerDimensionNameUpdated] [nvarchar](max) NULL,
	[CustVendNegInstProtestProcess] [nvarchar](max) NULL,
	[ReportingCurrencyFixedExchRate] [nvarchar](max) NULL,
	[InUseBy] [nvarchar](max) NULL,
	[RejectedBy] [nvarchar](max) NULL,
	[AssetTransferType_LT] [nvarchar](max) NULL,
	[ExchRate] [float] NULL,
	[ReportedAsReadyBy] [nvarchar](max) NULL,
	[Posted] [nvarchar](max) NULL,
	[SessionLoginDateTime] [datetime2](0) NULL,
	[SysCreatedBy] [nvarchar](max) NULL,
	[JournalTotalDebit] [float] NULL,
	[ParentJournalNum] [nvarchar](max) NULL,
	[NumberSequenceTable] [bigint] NULL,
	[BankTransSummarizationEnabled] [nvarchar](max) NULL,
	[journalTotalOffsetBalance] [float] NULL,
	[ProtestSettledBill] [nvarchar](max) NULL,
	[DocumentNum] [nvarchar](max) NULL,
	[LedgerJournalInclTax] [nvarchar](max) NULL,
	[OriginalCompany] [nvarchar](max) NULL,
	[Approver] [bigint] NULL,
	[WorkflowApprovalStatus] [nvarchar](max) NULL,
	[Name] [nvarchar](max) NULL,
	[BankTransSummarizationCriteria] [nvarchar](max) NULL,
	[ReportingCurrencyExchRate] [float] NULL,
	[NumOfLines] [bigint] NULL,
	[LinesLimitBeforeDistribution] [bigint] NULL,
	[OriginalJournalNum] [nvarchar](max) NULL,
	[TaxObligationCompany] [nvarchar](max) NULL,
	[UserBlockId] [nvarchar](max) NULL,
	[SysDataAreaId] [nvarchar](max) NULL,
	[PaymentsGenerated_IT] [nvarchar](max) NULL,
	[SystemBlocked] [nvarchar](max) NULL,
	[JournalTotalCreditReportingCurrency] [float] NULL,
	[Log] [nvarchar](max) NULL,
	[GroupBlockId] [nvarchar](max) NULL,
	[SysRecVersion] [bigint] NULL,
	[JournalTotalDebitReportingCurrency] [float] NULL,
	[JournalTotalCredit] [float] NULL,
	[SourceKey] [bigint] NULL,
	[BankAccountId] [nvarchar](max) NULL,
	[EndBalance] [float] NULL,
	[OverrideSalesTax] [nvarchar](max) NULL,
	[OffsetLedgerDimensionValuesJson] [nvarchar](max) NULL,
	[ExchrateSecondary] [float] NULL,
	[FixedOffsetAccount] [nvarchar](max) NULL,
	[CurrencyCode] [nvarchar](max) NULL,
	[ReportingCurrencyExchRateSecondary] [float] NULL,
	[FixedExchRate] [nvarchar](max) NULL,
	[DetailSummaryPosting] [nvarchar](max) NULL,
	[DelayTaxCalculation] [nvarchar](max) NULL,
	[SessionId] [bigint] NULL,
	[SysModifiedBy] [nvarchar](max) NULL,
	[IntegrationKey] [nvarchar](max) NULL,
	[IsAdjustmentJournal] [nvarchar](max) NULL,
	[CurrentOperationsTax] [nvarchar](max) NULL
) ON [PRIMARY] TEXTIMAGE_ON [PRIMARY]
GO
/****** Object:  Table [dbo].[LPO_Final_Order_Header]    Script Date: 30/07/2025 12:27:44 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[LPO_Final_Order_Header](
	[Purchase order] [varchar](41) NULL,
	[Vendor account] [varchar](14) NOT NULL,
	[Warehouse] [nvarchar](10) NULL,
	[Financial dimensions] [varchar](173) NULL,
	[ref] [nvarchar](24) NULL
) ON [PRIMARY]
GO
/****** Object:  Table [dbo].[LPO_Final_Order_Upload]    Script Date: 30/07/2025 12:27:44 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[LPO_Final_Order_Upload](
	[Purchase order] [varchar](16) NOT NULL,
	[Line number] [bigint] NULL,
	[Item number] [nvarchar](max) NULL,
	[Quantity] [int] NULL,
	[Unit] [nvarchar](max) NULL,
	[Unit price] [varchar](50) NULL,
	[FOC] [varchar](3) NOT NULL,
	[External item number] [varchar](1) NOT NULL,
	[Vendor] [varchar](14) NOT NULL,
	[ref] [nvarchar](max) NULL,
	[StoreCode] [nchar](10) NULL,
	[Tax] [varchar](50) NULL
) ON [PRIMARY] TEXTIMAGE_ON [PRIMARY]
GO
/****** Object:  Table [dbo].[LPO_Final_Order_Upload_bkup]    Script Date: 30/07/2025 12:27:44 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[LPO_Final_Order_Upload_bkup](
	[Purchase order] [varchar](16) NOT NULL,
	[Line number] [bigint] NULL,
	[Item number] [nvarchar](max) NULL,
	[Quantity] [int] NULL,
	[Unit] [nvarchar](max) NULL,
	[Unit price] [varchar](50) NULL,
	[FOC] [varchar](3) NOT NULL,
	[External item number] [varchar](1) NOT NULL,
	[Vendor] [varchar](14) NOT NULL,
	[ref] [nvarchar](max) NULL,
	[StoreCode] [nchar](10) NULL,
	[Tax] [varchar](50) NULL
) ON [PRIMARY] TEXTIMAGE_ON [PRIMARY]
GO
/****** Object:  Table [dbo].[Min_Change_Upload_Raw]    Script Date: 30/07/2025 12:27:44 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[Min_Change_Upload_Raw](
	[ItemNumber] [varchar](50) NULL,
	[SiteCode] [varchar](50) NULL,
	[Min] [varchar](50) NULL,
	[Max] [varchar](50) NULL
) ON [PRIMARY]
GO
/****** Object:  Table [dbo].[MIN_MAX_REFERENCE_CALCULATOR]    Script Date: 30/07/2025 12:27:44 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[MIN_MAX_REFERENCE_CALCULATOR](
	[ItemNumber] [nvarchar](max) NULL,
	[Drug_id] [varchar](50) NULL,
	[ProductName] [nvarchar](max) NULL,
	[STORECODE] [varchar](50) NULL,
	[LocationID] [varchar](50) NULL,
	[6MOS] [money] NOT NULL,
	[2M] [money] NOT NULL,
	[Stock] [numeric](38, 2) NOT NULL,
	[Min] [varchar](50) NULL,
	[Max] [varchar](50) NULL,
	[ShortName] [varchar](50) NULL
) ON [PRIMARY] TEXTIMAGE_ON [PRIMARY]
GO
/****** Object:  Table [dbo].[Min_Max_Udate_Upload]    Script Date: 30/07/2025 12:27:44 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[Min_Max_Udate_Upload](
	[Item Number] [varchar](50) NULL,
	[STORECODE] [varchar](50) NULL,
	[Min] [varchar](50) NULL,
	[Max] [varchar](50) NULL
) ON [PRIMARY]
GO
/****** Object:  Table [dbo].[Min_Max_Update_Upload_portal]    Script Date: 30/07/2025 12:27:44 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[Min_Max_Update_Upload_portal](
	[Item Number] [varchar](50) NULL,
	[STORECODE] [varchar](50) NULL,
	[Min] [varchar](50) NULL,
	[Max] [varchar](50) NULL
) ON [PRIMARY]
GO
/****** Object:  Table [dbo].[MinMax_QueryExecutionLog]    Script Date: 30/07/2025 12:27:44 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[MinMax_QueryExecutionLog](
	[LogID] [int] IDENTITY(1,1) NOT NULL,
	[QueryText] [nvarchar](max) NULL,
	[ExecutionDateTime] [datetime] NULL,
	[ResultMessage] [nvarchar](max) NULL,
	[RowsAffected] [int] NULL,
	[DurationMilliseconds] [int] NULL,
	[Duration] [nvarchar](max) NULL,
PRIMARY KEY CLUSTERED 
(
	[LogID] ASC
)WITH (PAD_INDEX = OFF, STATISTICS_NORECOMPUTE = OFF, IGNORE_DUP_KEY = OFF, ALLOW_ROW_LOCKS = ON, ALLOW_PAGE_LOCKS = ON, OPTIMIZE_FOR_SEQUENTIAL_KEY = OFF) ON [PRIMARY]
) ON [PRIMARY] TEXTIMAGE_ON [PRIMARY]
GO
/****** Object:  Table [dbo].[MixAndMatchLineGroups]    Script Date: 30/07/2025 12:27:44 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[MixAndMatchLineGroups](
	[dataAreaId] [nvarchar](max) NULL,
	[MixAndMatchOfferId] [nvarchar](max) NULL,
	[MixAndMatchLineGroup] [nvarchar](max) NULL,
	[DiscountLineColor] [bigint] NULL,
	[NumberOfItemsNeeded] [bigint] NULL
) ON [PRIMARY] TEXTIMAGE_ON [PRIMARY]
GO
/****** Object:  Table [dbo].[Mx_CallCenter_Agents]    Script Date: 30/07/2025 12:27:44 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[Mx_CallCenter_Agents](
	[SalesmanName] [varchar](50) NULL,
	[StaffID] [varchar](50) NULL,
	[Source] [varchar](50) NULL,
	[Target] [numeric](38, 0) NULL,
	[PL_Target] [numeric](38, 0) NULL
) ON [PRIMARY]
GO
/****** Object:  Table [dbo].[Mx_DIGITAL_ITEMS]    Script Date: 30/07/2025 12:27:44 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[Mx_DIGITAL_ITEMS](
	[ItemNumber] [nvarchar](max) NULL,
	[ProductName] [nvarchar](max) NULL
) ON [PRIMARY] TEXTIMAGE_ON [PRIMARY]
GO
/****** Object:  Table [dbo].[Mx_Expiry_for_Return_Policy_Upload_RAW]    Script Date: 30/07/2025 12:27:44 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[Mx_Expiry_for_Return_Policy_Upload_RAW](
	[Item number] [varchar](50) NULL,
	[Product name] [varchar](254) NULL,
	[Consignment item] [varchar](50) NULL,
	[Bonus Item] [varchar](50) NULL,
	[Warehouse] [varchar](50) NULL,
	[Batch number] [varchar](50) NULL,
	[Location] [varchar](50) NULL,
	[Warehouse Name] [varchar](50) NULL,
	[Primary Vendor] [varchar](50) NULL,
	[Vendor Name] [varchar](254) NULL,
	[Batch disposition code] [varchar](50) NULL,
	[Batch disposition status] [varchar](50) NULL,
	[Manufacturing date] [varchar](50) NULL,
	[Shelf life period in days] [varchar](50) NULL,
	[Expiration date] [varchar](50) NULL,
	[Physical inventory] [varchar](50) NULL,
	[Physical reserved] [varchar](50) NULL,
	[Available physical] [varchar](50) NULL,
	[Ordered] [varchar](50) NULL,
	[Ordered reserved] [varchar](50) NULL,
	[Total available] [varchar](50) NULL
) ON [PRIMARY]
GO
/****** Object:  Table [dbo].[Mx_Instashop]    Script Date: 30/07/2025 12:27:44 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[Mx_Instashop](
	[Barcode] [varchar](50) NULL,
	[DrugName] [varchar](254) NULL,
	[Branch] [nvarchar](8) NULL,
	[LocationID] [int] NOT NULL,
	[DRUG_ID] [nvarchar](25) NULL,
	[SP1] [money] NULL,
	[DateAdded] [smalldatetime] NULL
) ON [PRIMARY]
GO
/****** Object:  Table [dbo].[Mx_Item_Cost]    Script Date: 30/07/2025 12:27:44 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[Mx_Item_Cost](
	[ItemNumber] [int] NULL,
	[QuantityUnitSymbol] [varchar](255) NULL,
	[VendorAccountNumber] [varchar](255) NULL,
	[PriceApplicableFromDate] [varchar](255) NULL,
	[PriceApplicableToDate] [varchar](255) NULL,
	[Price] [float] NULL
) ON [PRIMARY]
GO
/****** Object:  Table [dbo].[Mx_Min_Max_Raw_Aug2024]    Script Date: 30/07/2025 12:27:44 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[Mx_Min_Max_Raw_Aug2024](
	[ItemNumber] [varchar](50) NULL,
	[SiteCode] [varchar](50) NULL,
	[Min] [varchar](50) NULL,
	[Max] [varchar](50) NULL,
	[LastModifiedDate] [datetime] NULL,
	[LastModifiedBy] [varchar](50) NULL
) ON [PRIMARY]
GO
/****** Object:  Table [dbo].[Mx_Min_Max_Raw_Upload_02062024]    Script Date: 30/07/2025 12:27:44 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[Mx_Min_Max_Raw_Upload_02062024](
	[ItemNumber] [varchar](50) NULL,
	[SiteCode] [varchar](50) NULL,
	[Min] [varchar](50) NULL,
	[Max] [varchar](50) NULL
) ON [PRIMARY]
GO
/****** Object:  Table [dbo].[Mx_Min_Max_Raw_Upload_0407]    Script Date: 30/07/2025 12:27:44 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[Mx_Min_Max_Raw_Upload_0407](
	[ItemNumber] [varchar](50) NULL,
	[SiteCode] [varchar](50) NULL,
	[Min] [varchar](50) NULL,
	[Max] [varchar](50) NULL,
	[LastModifiedDate] [datetime] NULL,
	[LastModifiedBy] [varchar](50) NULL
) ON [PRIMARY]
GO
/****** Object:  Table [dbo].[Mx_Min_Max_Raw_Upload_1]    Script Date: 30/07/2025 12:27:44 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[Mx_Min_Max_Raw_Upload_1](
	[ItemNumber] [varchar](50) NULL,
	[SiteCode] [varchar](50) NULL,
	[Min] [varchar](50) NULL,
	[Max] [varchar](50) NULL,
	[LastModifiedDate] [datetime] NULL,
	[LastModifiedBy] [varchar](50) NULL
) ON [PRIMARY]
GO
/****** Object:  Table [dbo].[Mx_Min_Max_Raw_Upload_10D]    Script Date: 30/07/2025 12:27:44 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[Mx_Min_Max_Raw_Upload_10D](
	[ItemNumber] [varchar](50) NULL,
	[SiteCode] [varchar](50) NULL,
	[Min] [varchar](50) NULL,
	[Max] [varchar](50) NULL
) ON [PRIMARY]
GO
/****** Object:  Table [dbo].[Mx_Min_Max_Raw_Upload_2507]    Script Date: 30/07/2025 12:27:44 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[Mx_Min_Max_Raw_Upload_2507](
	[ItemNumber] [varchar](50) NULL,
	[SiteCode] [varchar](50) NULL,
	[Min] [varchar](50) NULL,
	[Max] [varchar](50) NULL,
	[LastModifiedDate] [datetime] NULL,
	[LastModifiedBy] [varchar](50) NULL
) ON [PRIMARY]
GO
/****** Object:  Table [dbo].[Mx_Min_Max_Raw_Upload_history]    Script Date: 30/07/2025 12:27:44 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[Mx_Min_Max_Raw_Upload_history](
	[ID] [int] IDENTITY(1,1) NOT NULL,
	[ItemNumber] [varchar](50) NULL,
	[SiteCode] [varchar](50) NULL,
	[old_Min] [varchar](50) NULL,
	[Old_Max] [varchar](50) NULL,
	[New_Min] [varchar](50) NULL,
	[New_Max] [varchar](50) NULL,
	[Modified_Date] [datetime] NOT NULL,
	[Staff] [varchar](50) NOT NULL,
	[Remarks] [varchar](50) NULL
) ON [PRIMARY]
GO
/****** Object:  Table [dbo].[Mx_Min_Max_Raw_Upload_history4]    Script Date: 30/07/2025 12:27:44 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[Mx_Min_Max_Raw_Upload_history4](
	[ItemNumber] [varchar](50) NULL,
	[SiteCode] [varchar](50) NULL,
	[old_Min] [int] NULL,
	[Old_Max] [int] NULL,
	[New_Min] [int] NULL,
	[New_Max] [int] NULL,
	[Modified_Date] [datetime] NOT NULL,
	[Staff] [varchar](30) NULL,
	[Remarks] [varchar](9) NOT NULL,
	[Batch] [int] NULL
) ON [PRIMARY]
GO
/****** Object:  Table [dbo].[Mx_Min_Max_Raw_Upload_karban]    Script Date: 30/07/2025 12:27:44 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[Mx_Min_Max_Raw_Upload_karban](
	[ItemNumber] [varchar](50) NULL,
	[SiteCode] [varchar](50) NULL,
	[Min] [varchar](50) NULL,
	[Max] [varchar](50) NULL
) ON [PRIMARY]
GO
/****** Object:  Table [dbo].[Mx_Min_Max_Raw_Upload_MAIN_bkup]    Script Date: 30/07/2025 12:27:44 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[Mx_Min_Max_Raw_Upload_MAIN_bkup](
	[ItemNumber] [varchar](50) NULL,
	[SiteCode] [varchar](50) NULL,
	[Min] [varchar](50) NULL,
	[Max] [varchar](50) NULL
) ON [PRIMARY]
GO
/****** Object:  Table [dbo].[Mx_Min_Max_Raw_Upload_oct2024]    Script Date: 30/07/2025 12:27:44 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[Mx_Min_Max_Raw_Upload_oct2024](
	[ItemNumber] [varchar](50) NULL,
	[SiteCode] [varchar](50) NULL,
	[Min] [varchar](50) NULL,
	[Max] [varchar](50) NULL,
	[LastModifiedDate] [datetime] NULL,
	[LastModifiedBy] [varchar](50) NULL
) ON [PRIMARY]
GO
/****** Object:  Table [dbo].[Mx_Min_Max_Raw_Upload_previous]    Script Date: 30/07/2025 12:27:44 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[Mx_Min_Max_Raw_Upload_previous](
	[ItemNumber] [varchar](50) NULL,
	[SiteCode] [varchar](50) NULL,
	[Min] [varchar](50) NULL,
	[Max] [varchar](50) NULL,
	[LastModifiedDate] [datetime] NULL,
	[LastModifiedBy] [varchar](50) NULL
) ON [PRIMARY]
GO
/****** Object:  Table [dbo].[Mx_Min_Max_Raw_Upload_previous_0307]    Script Date: 30/07/2025 12:27:44 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[Mx_Min_Max_Raw_Upload_previous_0307](
	[ItemNumber] [varchar](50) NULL,
	[SiteCode] [varchar](50) NULL,
	[Min] [varchar](50) NULL,
	[Max] [varchar](50) NULL
) ON [PRIMARY]
GO
/****** Object:  Table [dbo].[Mx_Min_Max_Raw_Upload_previous_0407]    Script Date: 30/07/2025 12:27:44 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[Mx_Min_Max_Raw_Upload_previous_0407](
	[ItemNumber] [varchar](50) NULL,
	[SiteCode] [varchar](50) NULL,
	[Min] [varchar](50) NULL,
	[Max] [varchar](50) NULL
) ON [PRIMARY]
GO
/****** Object:  Table [dbo].[Mx_Min_Max_Raw_Upload_previous_0407_v2]    Script Date: 30/07/2025 12:27:44 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[Mx_Min_Max_Raw_Upload_previous_0407_v2](
	[ItemNumber] [varchar](50) NULL,
	[SiteCode] [varchar](50) NULL,
	[Min] [varchar](50) NULL,
	[Max] [varchar](50) NULL
) ON [PRIMARY]
GO
/****** Object:  Table [dbo].[Mx_Min_Max_Raw_Upload_previous_0907]    Script Date: 30/07/2025 12:27:44 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[Mx_Min_Max_Raw_Upload_previous_0907](
	[ItemNumber] [varchar](50) NULL,
	[SiteCode] [varchar](50) NULL,
	[Min] [varchar](50) NULL,
	[Max] [varchar](50) NULL
) ON [PRIMARY]
GO
/****** Object:  Table [dbo].[Mx_Min_Max_Raw_Upload_previous_1507]    Script Date: 30/07/2025 12:27:44 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[Mx_Min_Max_Raw_Upload_previous_1507](
	[ItemNumber] [varchar](50) NULL,
	[SiteCode] [varchar](50) NULL,
	[Min] [varchar](50) NULL,
	[Max] [varchar](50) NULL
) ON [PRIMARY]
GO
/****** Object:  Table [dbo].[Mx_Min_Max_Raw_Upload_previous_2107]    Script Date: 30/07/2025 12:27:44 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[Mx_Min_Max_Raw_Upload_previous_2107](
	[ItemNumber] [varchar](50) NULL,
	[SiteCode] [varchar](50) NULL,
	[Min] [varchar](50) NULL,
	[Max] [varchar](50) NULL
) ON [PRIMARY]
GO
/****** Object:  Table [dbo].[Mx_Min_Max_Raw_Upload_previous_2507]    Script Date: 30/07/2025 12:27:44 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[Mx_Min_Max_Raw_Upload_previous_2507](
	[ItemNumber] [varchar](50) NULL,
	[SiteCode] [varchar](50) NULL,
	[Min] [varchar](50) NULL,
	[Max] [varchar](50) NULL
) ON [PRIMARY]
GO
/****** Object:  Table [dbo].[Mx_Min_Max_Raw_Upload_previous2]    Script Date: 30/07/2025 12:27:44 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[Mx_Min_Max_Raw_Upload_previous2](
	[ItemNumber] [varchar](50) NULL,
	[SiteCode] [varchar](50) NULL,
	[Min] [varchar](50) NULL,
	[Max] [varchar](50) NULL
) ON [PRIMARY]
GO
/****** Object:  Table [dbo].[Mx_Min_Max_Raw_Upload_previous3]    Script Date: 30/07/2025 12:27:44 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[Mx_Min_Max_Raw_Upload_previous3](
	[ItemNumber] [varchar](50) NULL,
	[SiteCode] [varchar](50) NULL,
	[Min] [varchar](50) NULL,
	[Max] [varchar](50) NULL,
	[LastModifiedDate] [datetime] NULL,
	[LastModifiedBy] [varchar](50) NULL
) ON [PRIMARY]
GO
/****** Object:  Table [dbo].[Mx_Product_Category]    Script Date: 30/07/2025 12:27:44 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[Mx_Product_Category](
	[Drug_id] [varchar](50) NULL,
	[ItemNumber] [varchar](50) NULL,
	[DrugName] [varchar](254) NULL,
	[New Category] [varchar](50) NULL
) ON [PRIMARY]
GO
/****** Object:  Table [dbo].[MX_Product_Cost_SPrice_bkup]    Script Date: 30/07/2025 12:27:44 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[MX_Product_Cost_SPrice_bkup](
	[Item number] [varchar](50) NULL,
	[Product name] [varchar](254) NULL,
	[Price] [varchar](50) NULL,
	[Item sales tax group] [varchar](50) NULL,
	[Price2] [varchar](50) NULL,
	[Vendor] [varchar](50) NULL
) ON [PRIMARY]
GO
/****** Object:  Table [dbo].[MX_Product_Cost_SPrice_Upload_Raw_bkup]    Script Date: 30/07/2025 12:27:44 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[MX_Product_Cost_SPrice_Upload_Raw_bkup](
	[Item number] [varchar](50) NULL,
	[Product name] [varchar](254) NULL,
	[Price] [varchar](50) NULL,
	[Item sales tax group] [varchar](50) NULL,
	[Price2] [varchar](50) NULL,
	[Vendor] [varchar](50) NULL
) ON [PRIMARY]
GO
/****** Object:  Table [dbo].[Mx_Product_Order_Group]    Script Date: 30/07/2025 12:27:44 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[Mx_Product_Order_Group](
	[Drug_id] [varchar](50) NULL,
	[DrugName] [varchar](254) NULL,
	[Order_Group] [varchar](50) NULL
) ON [PRIMARY]
GO
/****** Object:  Table [dbo].[Mx_Product_Order_Group_ALL_WH]    Script Date: 30/07/2025 12:27:44 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[Mx_Product_Order_Group_ALL_WH](
	[Drug_id] [varchar](50) NULL,
	[DrugName] [varchar](254) NULL,
	[Order_Group] [varchar](50) NULL
) ON [PRIMARY]
GO
/****** Object:  Table [dbo].[Mx_Product_Order_Group_bkup_0503]    Script Date: 30/07/2025 12:27:44 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[Mx_Product_Order_Group_bkup_0503](
	[Drug_id] [varchar](50) NULL,
	[DrugName] [varchar](254) NULL,
	[Order_Group] [varchar](50) NULL
) ON [PRIMARY]
GO
/****** Object:  Table [dbo].[Mx_Product_w_Price_Tax]    Script Date: 30/07/2025 12:27:44 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[Mx_Product_w_Price_Tax](
	[ItemNumber] [nvarchar](max) NULL,
	[ProductName] [nvarchar](max) NULL,
	[Drug_id] [varchar](50) NULL,
	[SalesSalesTaxItemGroupCode] [nvarchar](max) NULL,
	[SalesUnitSymbol] [nvarchar](max) NULL,
	[Cost] [varchar](50) NULL,
	[Selling_Price] [varchar](50) NULL
) ON [PRIMARY] TEXTIMAGE_ON [PRIMARY]
GO
/****** Object:  Table [dbo].[Mx_Stocks_by_Location]    Script Date: 30/07/2025 12:27:44 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[Mx_Stocks_by_Location](
	[Item number] [varchar](50) NULL,
	[Product name] [varchar](254) NULL,
	[DrugName] [varchar](254) NULL,
	[Drug_ID] [varchar](50) NULL,
	[Site] [varchar](50) NULL,
	[STORENAME] [varchar](50) NULL,
	[ShortName] [varchar](50) NULL,
	[Available physical] [decimal](8, 2) NULL,
	[LocationID] [varchar](50) NULL,
	[LastUpdate] [datetime] NULL,
	[Site2] [varchar](101) NULL,
	[UNITCOST] [money] NULL
) ON [PRIMARY]
GO
/****** Object:  Table [dbo].[Mx_Vendor_Master]    Script Date: 30/07/2025 12:27:44 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[Mx_Vendor_Master](
	[Vendor account] [varchar](50) NULL,
	[Name] [varchar](254) NULL,
	[Vendor hold] [varchar](50) NULL,
	[Phone] [varchar](50) NULL,
	[Extension] [varchar](50) NULL,
	[Primary contact] [varchar](50) NULL,
	[Group] [varchar](50) NULL,
	[Currency] [varchar](50) NULL
) ON [PRIMARY]
GO
/****** Object:  Table [dbo].[Negtaive sales2]    Script Date: 30/07/2025 12:27:44 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[Negtaive sales2](
	[Statement number] [varchar](50) NULL,
	[Store Code] [varchar](50) NULL,
	[Item number] [varchar](50) NULL,
	[Item Name] [varchar](250) NULL,
	[Site] [varchar](50) NULL,
	[Warehouse] [varchar](50) NULL,
	[Location] [varchar](50) NULL,
	[Batch number] [varchar](50) NULL,
	[Expiry Date] [varchar](50) NULL,
	[Unit] [varchar](50) NULL,
	[Sales qty] [varchar](50) NULL,
	[Available qty] [varchar](150) NULL
) ON [PRIMARY]
GO
/****** Object:  Table [dbo].[Negtaive_sales_final_crm]    Script Date: 30/07/2025 12:27:44 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[Negtaive_sales_final_crm](
	[Store Code] [varchar](50) NULL,
	[Item number] [varchar](50) NULL,
	[Item Name] [varchar](254) NULL,
	[Site] [varchar](50) NULL,
	[Warehouse] [varchar](50) NULL,
	[Location] [varchar](50) NULL,
	[Batch number] [varchar](50) NULL,
	[Expiry Date] [varchar](1) NOT NULL,
	[Unit] [varchar](1) NOT NULL,
	[Sales qty1] [decimal](38, 2) NULL,
	[Available qty] [varchar](1) NOT NULL,
	[Sales qty] [decimal](38, 2) NULL,
	[ref] [varchar](100) NULL,
	[Seq] [bigint] NULL,
	[Line_Count] [int] NULL,
	[Order_id] [varchar](50) NULL,
	[Branch_name] [varchar](50) NULL,
	[Validation] [varchar](254) NULL,
	[On_Hand] [varchar](254) NULL
) ON [PRIMARY]
GO
/****** Object:  Table [dbo].[Negtaive_sales_final_crm_RAW]    Script Date: 30/07/2025 12:27:44 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[Negtaive_sales_final_crm_RAW](
	[Store Code] [varchar](50) NULL,
	[Item number] [varchar](50) NULL,
	[Item Name] [varchar](254) NULL,
	[ref] [varchar](100) NULL,
	[Seq] [bigint] NULL,
	[Line_Count] [int] NULL,
	[Validation] [varchar](254) NULL,
	[On_Hand] [varchar](254) NULL,
	[Selling Batch number] [varchar](50) NULL,
	[Sales qty] [decimal](38, 2) NULL,
	[Found Batch] [varchar](50) NULL,
	[Qty Needed] [decimal](38, 2) NULL,
	[Qty Available] [varchar](50) NULL,
	[Line_Remarks] [varchar](28) NULL,
	[Group_Remarks] [varchar](19) NOT NULL,
	[Order_id] [varchar](50) NULL,
	[Branch_name] [varchar](50) NULL
) ON [PRIMARY]
GO
/****** Object:  Table [dbo].[OLE DB Destination]    Script Date: 30/07/2025 12:27:44 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[OLE DB Destination](
	[dataAreaId] [nvarchar](max) NULL,
	[ItemNumber] [nvarchar](max) NULL,
	[SiteId] [nvarchar](max) NULL,
	[WarehouseId] [nvarchar](max) NULL,
	[InventoryStatus] [nvarchar](max) NULL,
	[AvailPhysical] [numeric](38, 0) NULL,
	[CalculatedAvailablePhysical] [numeric](38, 0) NULL
) ON [PRIMARY] TEXTIMAGE_ON [PRIMARY]
GO
/****** Object:  Table [dbo].[ON hand Stock]    Script Date: 30/07/2025 12:27:44 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[ON hand Stock](
	[Item number] [varchar](50) NULL,
	[Product name] [varchar](50) NULL,
	[Search name] [varchar](50) NULL,
	[Consignment item] [varchar](50) NULL,
	[Warehouse] [varchar](50) NULL,
	[Batch number] [varchar](50) NULL,
	[Location] [varchar](50) NULL,
	[Warehouse name] [varchar](50) NULL,
	[Physical inventory] [varchar](50) NULL,
	[Physical reserved] [varchar](50) NULL,
	[Available physical] [varchar](50) NULL,
	[Available physical on exact dimensions] [varchar](50) NULL,
	[Ordered in total] [varchar](50) NULL,
	[On order] [varchar](50) NULL,
	[Ordered reserved] [varchar](50) NULL,
	[Available for reservation] [varchar](50) NULL,
	[Total available] [varchar](50) NULL,
	[Uses warehouse management processes] [varchar](50) NULL,
	[Product identification] [varchar](50) NULL
) ON [PRIMARY]
GO
/****** Object:  Table [dbo].[ON hand Stock2]    Script Date: 30/07/2025 12:27:44 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[ON hand Stock2](
	[Item number] [varchar](50) NULL,
	[Product name] [varchar](254) NULL,
	[Search name] [varchar](254) NULL,
	[Consignment item] [varchar](50) NULL,
	[Warehouse] [varchar](50) NULL,
	[Batch number] [varchar](50) NULL,
	[Location] [varchar](50) NULL,
	[Warehouse name] [varchar](50) NULL,
	[Physical inventory] [varchar](50) NULL,
	[Physical reserved] [varchar](50) NULL,
	[Available physical] [varchar](50) NULL,
	[Available physical on exact dimensions] [varchar](50) NULL,
	[Ordered in total] [varchar](50) NULL,
	[On order] [varchar](50) NULL,
	[Ordered reserved] [varchar](50) NULL,
	[Available for reservation] [varchar](50) NULL,
	[Total available] [varchar](50) NULL,
	[Uses warehouse management processes] [varchar](50) NULL,
	[Product identification] [varchar](50) NULL
) ON [PRIMARY]
GO
/****** Object:  Table [dbo].[Order_Template_Upload]    Script Date: 30/07/2025 12:27:44 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[Order_Template_Upload](
	[ItemNumber] [varchar](50) NULL,
	[StoreCode] [varchar](50) NULL,
	[Order] [varchar](50) NULL,
	[Bonus] [varchar](50) NULL,
	[Vendor] [varchar](50) NULL,
	[ref] [varchar](50) NULL
) ON [PRIMARY]
GO
/****** Object:  Table [dbo].[Portal_Log]    Script Date: 30/07/2025 12:27:44 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[Portal_Log](
	[locationid] [nchar](10) NULL,
	[lastActivity] [datetime2](7) NULL,
	[process] [varchar](254) NULL,
	[ipaddress] [nvarchar](50) NULL,
	[pcname] [nvarchar](50) NULL,
	[username] [nvarchar](50) NULL
) ON [PRIMARY]
GO
/****** Object:  Table [dbo].[PostdatedChecks_orig]    Script Date: 30/07/2025 12:27:44 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[PostdatedChecks_orig](
	[dataAreaId] [varchar](255) NULL,
	[JournalBatchNumber] [varchar](255) NULL,
	[LineNumber] [int] NULL,
	[CreditAmount] [int] NULL,
	[AccountDisplayValue] [varchar](255) NULL,
	[IsPaymentStopped] [varchar](255) NULL,
	[PostDatedCheckStatus] [varchar](255) NULL,
	[CurrencyCode] [varchar](255) NULL,
	[IsReplacementCheck] [varchar](255) NULL,
	[TransactionDate] [varchar](255) NULL,
	[DebitAmount] [float] NULL,
	[Voucher] [varchar](255) NULL,
	[AccountType] [varchar](255) NULL,
	[CheckNumber] [int] NULL,
	[MaturityDate] [varchar](255) NULL,
	[LastUpdate] [datetime] NULL
) ON [PRIMARY]
GO
/****** Object:  Table [dbo].[PowerBi_Update_Log]    Script Date: 30/07/2025 12:27:44 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[PowerBi_Update_Log](
	[ID] [int] IDENTITY(1,1) NOT NULL,
	[ProcessName] [varchar](50) NULL,
	[StartDateTime] [datetime] NULL,
	[EndDateTime] [datetime] NULL,
	[Remarks] [varchar](50) NULL,
	[Rows] [int] NULL
) ON [PRIMARY]
GO
/****** Object:  Table [dbo].[ProductMaster_Upload__]    Script Date: 30/07/2025 12:27:44 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[ProductMaster_Upload__](
	[Product Id] [varchar](50) NULL,
	[Product Name] [varchar](254) NULL,
	[Unit] [varchar](50) NULL,
	[Brand] [varchar](50) NULL,
	[Main Category] [varchar](50) NULL,
	[Sub Category] [varchar](50) NULL,
	[Category] [varchar](50) NULL,
	[Sub Category 1] [varchar](50) NULL,
	[Generic] [varchar](50) NULL,
	[Is Marina] [varchar](50) NULL,
	[Supplier Id] [varchar](50) NULL,
	[Supplier] [varchar](254) NULL,
	[Tax Group] [varchar](50) NULL,
	[unit cost] [varchar](50) NULL,
	[Sales Price] [varchar](50) NULL,
	[Aggrement_Cost] [varchar](50) NULL,
	[Retail Price] [varchar](50) NULL,
	[Hotel Price] [varchar](50) NULL,
	[Is Active] [varchar](50) NULL
) ON [PRIMARY]
GO
/****** Object:  Table [dbo].[ProductMaster_Upload_3]    Script Date: 30/07/2025 12:27:44 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[ProductMaster_Upload_3](
	[Product Id] [varchar](50) NULL,
	[Product Name] [varchar](254) NULL,
	[Unit] [varchar](50) NULL,
	[Brand] [varchar](50) NULL,
	[Main Category] [varchar](50) NULL,
	[Sub Category] [varchar](254) NULL,
	[Category] [varchar](254) NULL,
	[Sub Category 1] [varchar](254) NULL,
	[Generic] [varchar](254) NULL,
	[Is Marina] [varchar](50) NULL,
	[Supplier Id] [varchar](50) NULL,
	[Supplier] [varchar](254) NULL,
	[Tax Group] [varchar](254) NULL,
	[unit cost] [varchar](50) NULL,
	[Sales Price] [varchar](50) NULL,
	[Aggrement_Cost] [varchar](50) NULL,
	[Retail Price] [varchar](50) NULL,
	[Hotel Price] [varchar](50) NULL,
	[Is Active] [varchar](50) NULL
) ON [PRIMARY]
GO
/****** Object:  Table [dbo].[ProductMaster_Upload2]    Script Date: 30/07/2025 12:27:44 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[ProductMaster_Upload2](
	[Product Id] [varchar](50) NULL,
	[Product Name] [varchar](254) NULL,
	[Unit] [varchar](50) NULL,
	[Brand] [varchar](50) NULL,
	[Main Category] [varchar](50) NULL,
	[Sub Category] [varchar](50) NULL,
	[Category] [varchar](50) NULL,
	[Sub Category 1] [varchar](50) NULL,
	[Generic] [varchar](254) NULL,
	[Is Marina] [varchar](50) NULL,
	[Supplier Id] [varchar](50) NULL,
	[Supplier] [varchar](254) NULL,
	[Tax Group] [varchar](50) NULL,
	[unit cost] [varchar](50) NULL,
	[Sales Price] [varchar](50) NULL,
	[Aggrement_Cost] [varchar](50) NULL,
	[Retail Price] [varchar](50) NULL,
	[Hotel Price] [varchar](50) NULL,
	[Is Active] [varchar](50) NULL
) ON [PRIMARY]
GO
/****** Object:  Table [dbo].[ProductMaster_Upload222]    Script Date: 30/07/2025 12:27:44 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[ProductMaster_Upload222](
	[Product Id] [nvarchar](255) NULL,
	[Product Name] [nvarchar](255) NULL,
	[Unit] [nvarchar](255) NULL,
	[Brand] [nvarchar](255) NULL,
	[Main Category] [nvarchar](255) NULL,
	[Sub Category] [nvarchar](255) NULL,
	[Category] [nvarchar](255) NULL,
	[Sub Category#1] [nvarchar](255) NULL,
	[Generic] [nvarchar](255) NULL,
	[Is Marina] [nvarchar](255) NULL,
	[Supplier Id] [nvarchar](255) NULL,
	[Supplier] [nvarchar](255) NULL,
	[Tax Group] [nvarchar](255) NULL,
	[unit cost] [float] NULL,
	[Sales Price] [float] NULL,
	[Aggrement_Cost] [float] NULL,
	[Retail Price] [float] NULL,
	[Hotel Price] [float] NULL,
	[Is Active] [nvarchar](255) NULL
) ON [PRIMARY]
GO
/****** Object:  Table [dbo].[ProductReceiptHeaders]    Script Date: 30/07/2025 12:27:44 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[ProductReceiptHeaders](
	[dataAreaId] [nvarchar](max) NULL,
	[RecordId] [bigint] NULL,
	[IsDeliveryAddressPrivate] [nvarchar](max) NULL,
	[DeliveryModeId] [nvarchar](max) NULL,
	[DeliveryAddressCountryRegionISOCode] [nvarchar](max) NULL,
	[DeliveryAddressPostBox] [nvarchar](max) NULL,
	[OrderVendorAccountNumber] [nvarchar](max) NULL,
	[DeliveryTermsId] [nvarchar](max) NULL,
	[RequesterPersonnelNumber] [nvarchar](max) NULL,
	[DeliveryAddressLatitude] [float] NULL,
	[DeliveryAddressName] [nvarchar](max) NULL,
	[DeliveryCityInKana] [nvarchar](max) NULL,
	[DeliveryAddressStreetNumber] [nvarchar](max) NULL,
	[DeliveryAddressTimeZone] [nvarchar](max) NULL,
	[DeliveryAddressZipCode] [nvarchar](max) NULL,
	[DeliveryAddressLocationId] [nvarchar](max) NULL,
	[DeliveryAddressCountyId] [nvarchar](max) NULL,
	[DeliveryBuildingCompliment] [nvarchar](max) NULL,
	[DeliveryAddressDistrictName] [nvarchar](max) NULL,
	[ProductReceiptNumber] [nvarchar](max) NULL,
	[DeliveryAddressDescription] [nvarchar](max) NULL,
	[FormattedDeliveryAddress] [nvarchar](max) NULL,
	[DeliveryAddressCountryRegionId] [nvarchar](max) NULL,
	[PurchaseOrderNumber] [nvarchar](max) NULL,
	[ProductReceiptDate] [datetime2](0) NULL,
	[DeliveryAddressStreet] [nvarchar](max) NULL,
	[DeliveryStreetInKana] [nvarchar](max) NULL,
	[DeliveryAddressLongitude] [float] NULL,
	[DeliveryAddressCity] [nvarchar](max) NULL,
	[DeliveryAddressStateId] [nvarchar](max) NULL,
	[AttentionInformation] [nvarchar](max) NULL,
	[DeliveryAddressDunsNumber] [nvarchar](max) NULL
) ON [PRIMARY] TEXTIMAGE_ON [PRIMARY]
GO
/****** Object:  Table [dbo].[ProductReceiptHeaders_1M]    Script Date: 30/07/2025 12:27:44 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[ProductReceiptHeaders_1M](
	[dataAreaId] [nvarchar](max) NULL,
	[RecordId] [bigint] NULL,
	[IsDeliveryAddressPrivate] [nvarchar](max) NULL,
	[DeliveryModeId] [nvarchar](max) NULL,
	[DeliveryAddressCountryRegionISOCode] [nvarchar](max) NULL,
	[DeliveryAddressPostBox] [nvarchar](max) NULL,
	[OrderVendorAccountNumber] [nvarchar](max) NULL,
	[DeliveryTermsId] [nvarchar](max) NULL,
	[RequesterPersonnelNumber] [nvarchar](max) NULL,
	[DeliveryAddressLatitude] [float] NULL,
	[DeliveryAddressName] [nvarchar](max) NULL,
	[DeliveryCityInKana] [nvarchar](max) NULL,
	[DeliveryAddressStreetNumber] [nvarchar](max) NULL,
	[DeliveryAddressTimeZone] [nvarchar](max) NULL,
	[DeliveryAddressZipCode] [nvarchar](max) NULL,
	[DeliveryAddressLocationId] [nvarchar](max) NULL,
	[DeliveryAddressCountyId] [nvarchar](max) NULL,
	[DeliveryBuildingCompliment] [nvarchar](max) NULL,
	[DeliveryAddressDistrictName] [nvarchar](max) NULL,
	[ProductReceiptNumber] [nvarchar](max) NULL,
	[DeliveryAddressDescription] [nvarchar](max) NULL,
	[FormattedDeliveryAddress] [nvarchar](max) NULL,
	[DeliveryAddressCountryRegionId] [nvarchar](max) NULL,
	[PurchaseOrderNumber] [nvarchar](max) NULL,
	[ProductReceiptDate] [datetime2](0) NULL,
	[DeliveryAddressStreet] [nvarchar](max) NULL,
	[DeliveryStreetInKana] [nvarchar](max) NULL,
	[DeliveryAddressLongitude] [float] NULL,
	[DeliveryAddressCity] [nvarchar](max) NULL,
	[DeliveryAddressStateId] [nvarchar](max) NULL,
	[AttentionInformation] [nvarchar](max) NULL,
	[DeliveryAddressDunsNumber] [nvarchar](max) NULL
) ON [PRIMARY] TEXTIMAGE_ON [PRIMARY]
GO
/****** Object:  Table [dbo].[ProductReceiptLines_1M]    Script Date: 30/07/2025 12:27:44 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[ProductReceiptLines_1M](
	[dataAreaId] [nvarchar](max) NULL,
	[RecordId] [bigint] NULL,
	[ReceivedPurchaseQuantity] [float] NULL,
	[ProductConfigurationId] [nvarchar](max) NULL,
	[ReceivedInventoryQuantity] [float] NULL,
	[PurchaseUnitSymbol] [nvarchar](max) NULL,
	[LineNumber] [float] NULL,
	[LineDescription] [nvarchar](max) NULL,
	[ProductNumber] [nvarchar](max) NULL,
	[ProductSizeId] [nvarchar](max) NULL,
	[ItemNumber] [nvarchar](max) NULL,
	[ProductVersionId] [nvarchar](max) NULL,
	[ItemSerialNumber] [nvarchar](max) NULL,
	[ReceivingSiteId] [nvarchar](max) NULL,
	[ReceivedInventoryStatusId] [nvarchar](max) NULL,
	[DeliveryAddressCountyId] [nvarchar](max) NULL,
	[ProductReceiptNumber] [nvarchar](max) NULL,
	[ProcurementProductCategoryHierarchyName] [nvarchar](max) NULL,
	[ExpectedDeliveryDate] [datetime2](0) NULL,
	[RemainingInventoryQuantity] [float] NULL,
	[DeliveryAddressCountryRegionId] [nvarchar](max) NULL,
	[PurchaseOrderNumber] [nvarchar](max) NULL,
	[ProductReceiptDate] [datetime2](0) NULL,
	[ExternalItemNumber] [nvarchar](max) NULL,
	[OrderedPurchaseQuantity] [float] NULL,
	[PurchaserPersonnelNumber] [nvarchar](max) NULL,
	[ReceivingWarehouseId] [nvarchar](max) NULL,
	[ProcurementProductCategoryName] [nvarchar](max) NULL,
	[ItemBatchNumber] [nvarchar](max) NULL,
	[RemainingPurchaseQuantity] [float] NULL,
	[ProductColorId] [nvarchar](max) NULL,
	[ProductReceiptHeaderRecordId] [bigint] NULL,
	[DeliveryAddressStateId] [nvarchar](max) NULL,
	[PurchaseOrderLineNumber] [bigint] NULL,
	[ReceivingWarehouseLocationId] [nvarchar](max) NULL,
	[ProductStyleId] [nvarchar](max) NULL
) ON [PRIMARY] TEXTIMAGE_ON [PRIMARY]
GO
/****** Object:  Table [dbo].[ProductSpecificUnitOfMeasureConversions1]    Script Date: 30/07/2025 12:27:44 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[ProductSpecificUnitOfMeasureConversions1](
	[ProductNumber] [nvarchar](max) NULL,
	[FromUnitSymbol] [nvarchar](max) NULL,
	[ToUnitSymbol] [nvarchar](max) NULL,
	[Factor] [float] NULL,
	[InnerOffset] [float] NULL,
	[OuterOffset] [float] NULL,
	[Rounding] [nvarchar](max) NULL,
	[Denominator] [bigint] NULL,
	[Numerator] [bigint] NULL
) ON [PRIMARY] TEXTIMAGE_ON [PRIMARY]
GO
/****** Object:  Table [dbo].[PurchaseOrder_Status]    Script Date: 30/07/2025 12:27:44 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[PurchaseOrder_Status](
	[PurchaseOrderNumber] [nvarchar](max) NULL,
	[ReceivingWarehouseId] [nvarchar](max) NULL,
	[RequestedDeliveryDate] [datetime2](0) NULL,
	[LineNumber] [bigint] NULL,
	[ItemNumber] [nvarchar](max) NULL,
	[LineDescription] [nvarchar](max) NULL,
	[OrderedPurchaseQuantity] [float] NULL,
	[Received] [float] NOT NULL,
	[Remaining] [float] NOT NULL,
	[PurchaseOrderLineStatus] [nvarchar](max) NULL,
	[PurchaseOrderStatus] [nvarchar](max) NULL,
	[Remarks] [varchar](16) NOT NULL,
	[DocumentApprovalStatus] [nvarchar](max) NULL
) ON [PRIMARY] TEXTIMAGE_ON [PRIMARY]
GO
/****** Object:  Table [dbo].[PurchaseOrderConfirmationLines_distinct]    Script Date: 30/07/2025 12:27:44 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[PurchaseOrderConfirmationLines_distinct](
	[PurchaseOrderNumber] [nvarchar](max) NULL,
	[ConfirmationDate] [datetime2](0) NULL
) ON [PRIMARY] TEXTIMAGE_ON [PRIMARY]
GO
/****** Object:  Table [dbo].[PurchaseOrderHeadersV2_1M]    Script Date: 30/07/2025 12:27:44 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[PurchaseOrderHeadersV2_1M](
	[dataAreaId] [nvarchar](max) NULL,
	[PurchaseOrderNumber] [nvarchar](max) NULL,
	[ExpectedStoreAvailableSalesDate] [datetime2](0) NULL,
	[VendorInvoiceDeclarationId] [nvarchar](max) NULL,
	[DeliveryModeId] [nvarchar](max) NULL,
	[InvoiceAddressStreet] [nvarchar](max) NULL,
	[OrderVendorAccountNumber] [nvarchar](max) NULL,
	[Email] [nvarchar](max) NULL,
	[TransportationModeId] [nvarchar](max) NULL,
	[IsChangeManagementActive] [nvarchar](max) NULL,
	[AccountingDistributionTemplateName] [nvarchar](max) NULL,
	[DeliveryAddressDescription] [nvarchar](max) NULL,
	[VendorTransactionSettlementType] [nvarchar](max) NULL,
	[DeliveryCityInKana] [nvarchar](max) NULL,
	[DeliveryStreetInKana] [nvarchar](max) NULL,
	[ReasonComment] [nvarchar](max) NULL,
	[NumberSequenceGroupId] [nvarchar](max) NULL,
	[TransportationTemplateId] [nvarchar](max) NULL,
	[AccountingDate] [datetime2](0) NULL,
	[CashDiscountPercentage] [float] NULL,
	[PurchaseOrderName] [nvarchar](max) NULL,
	[RequestedDeliveryDate] [datetime2](0) NULL,
	[DeliveryAddressCountryRegionId] [nvarchar](max) NULL,
	[DeliveryAddressLatitude] [float] NULL,
	[MultilineDiscountVendorGroupCode] [nvarchar](max) NULL,
	[DeliveryAddressCity] [nvarchar](max) NULL,
	[ConfirmedDeliveryDate] [datetime2](0) NULL,
	[PurchaseRebateVendorGroupId] [nvarchar](max) NULL,
	[InvoiceAddressCounty] [nvarchar](max) NULL,
	[ChargeVendorGroupId] [nvarchar](max) NULL,
	[RequesterPersonnelNumber] [nvarchar](max) NULL,
	[ProjectId] [nvarchar](max) NULL,
	[ShippingCarrierId] [nvarchar](max) NULL,
	[TotalDiscountPercentage] [float] NULL,
	[DeliveryAddressDistrictName] [nvarchar](max) NULL,
	[PriceVendorGroupCode] [nvarchar](max) NULL,
	[PurchaseOrderHeaderCreationMethod] [nvarchar](max) NULL,
	[DeliveryAddressCountyId] [nvarchar](max) NULL,
	[DeliveryAddressZipCode] [nvarchar](max) NULL,
	[IsConsolidatedInvoiceTarget] [nvarchar](max) NULL,
	[ConfirmingPurchaseOrderCode] [nvarchar](max) NULL,
	[LanguageId] [nvarchar](max) NULL,
	[ReasonCode] [nvarchar](max) NULL,
	[DeliveryAddressDunsNumber] [nvarchar](max) NULL,
	[DeliveryTermsId] [nvarchar](max) NULL,
	[BankDocumentType] [nvarchar](max) NULL,
	[ExpectedStoreReceiptDate] [datetime2](0) NULL,
	[DeliveryAddressName] [nvarchar](max) NULL,
	[InvoiceAddressCountryRegionId] [nvarchar](max) NULL,
	[ReplenishmentServiceCategoryId] [nvarchar](max) NULL,
	[PurchaseOrderPoolId] [nvarchar](max) NULL,
	[DeliveryAddressStreetNumber] [nvarchar](max) NULL,
	[RequestedShipDate] [datetime2](0) NULL,
	[ExpectedCrossDockingDate] [datetime2](0) NULL,
	[InvoiceAddressStreetNumber] [nvarchar](max) NULL,
	[IsDeliveryAddressPrivate] [nvarchar](max) NULL,
	[TaxExemptNumber] [nvarchar](max) NULL,
	[FormattedInvoiceAddress] [nvarchar](max) NULL,
	[BuyerGroupId] [nvarchar](max) NULL,
	[DeliveryAddressCountryRegionISOCode] [nvarchar](max) NULL,
	[CashDiscountCode] [nvarchar](max) NULL,
	[PaymentScheduleName] [nvarchar](max) NULL,
	[IntrastatTransactionCode] [nvarchar](max) NULL,
	[URL] [nvarchar](max) NULL,
	[CurrencyCode] [nvarchar](max) NULL,
	[ConfirmingPurchaseOrderCodeLanguageId] [nvarchar](max) NULL,
	[InvoiceType] [nvarchar](max) NULL,
	[ArePricesIncludingSalesTax] [nvarchar](max) NULL,
	[DeliveryAddressLocationId] [nvarchar](max) NULL,
	[GSTSelfBilledInvoiceApprovalNumber] [nvarchar](max) NULL,
	[IsDeliveredDirectly] [nvarchar](max) NULL,
	[ConfirmedShipDate] [datetime2](0) NULL,
	[ShipCalendarId] [nvarchar](max) NULL,
	[IntrastatStatisticsProcedureCode] [nvarchar](max) NULL,
	[InvoiceVendorAccountNumber] [nvarchar](max) NULL,
	[OverrideSalesTax] [nvarchar](max) NULL,
	[DeliveryAddressStreet] [nvarchar](max) NULL,
	[VendorOrderReference] [nvarchar](max) NULL,
	[ReplenishmentWarehouseId] [nvarchar](max) NULL,
	[FixedDueDate] [datetime2](0) NULL,
	[TransportationDocumentLineId] [nvarchar](max) NULL,
	[SalesTaxGroupCode] [nvarchar](max) NULL,
	[IsDeliveryAddressOrderSpecific] [nvarchar](max) NULL,
	[VendorPostingProfileId] [nvarchar](max) NULL,
	[VendorPaymentMethodSpecificationName] [nvarchar](max) NULL,
	[InvoiceAddressCity] [nvarchar](max) NULL,
	[ShippingCarrierServiceGroupId] [nvarchar](max) NULL,
	[ContactPersonId] [nvarchar](max) NULL,
	[DefaultReceivingWarehouseId] [nvarchar](max) NULL,
	[EUSalesListCode] [nvarchar](max) NULL,
	[ImportDeclarationNumber] [nvarchar](max) NULL,
	[PurchaseOrderStatus] [nvarchar](max) NULL,
	[PaymentTermsName] [nvarchar](max) NULL,
	[DeliveryAddressLongitude] [float] NULL,
	[DocumentApprovalStatus] [nvarchar](max) NULL,
	[InvoiceAddressZipCode] [nvarchar](max) NULL,
	[ShippingCarrierServiceId] [nvarchar](max) NULL,
	[DefaultLedgerDimensionDisplayValue] [nvarchar](max) NULL,
	[DeliveryAddressTimeZone] [nvarchar](max) NULL,
	[AttentionInformation] [nvarchar](max) NULL,
	[DeliveryAddressStateId] [nvarchar](max) NULL,
	[DeliveryBuildingCompliment] [nvarchar](max) NULL,
	[IntrastatTransportModeCode] [nvarchar](max) NULL,
	[DeliveryAddressPostBox] [nvarchar](max) NULL,
	[IsOneTimeVendor] [nvarchar](max) NULL,
	[IntrastatPortId] [nvarchar](max) NULL,
	[OrdererPersonnelNumber] [nvarchar](max) NULL,
	[VendorPaymentMethodName] [nvarchar](max) NULL,
	[InvoiceAddressState] [nvarchar](max) NULL,
	[DefaultReceivingSiteId] [nvarchar](max) NULL,
	[LineDiscountVendorGroupCode] [nvarchar](max) NULL,
	[TransportationRoutePlanId] [nvarchar](max) NULL,
	[ZakatContractNumber] [nvarchar](max) NULL,
	[FormattedDeliveryAddress] [nvarchar](max) NULL,
	[TotalDiscountVendorGroupCode] [nvarchar](max) NULL,
	[TradeEndCustomerAccount] [nvarchar](max) NULL,
	[FiscalDocumentOperationTypeId] [nvarchar](max) NULL,
	[FinTagDisplayValue] [nvarchar](max) NULL
) ON [PRIMARY] TEXTIMAGE_ON [PRIMARY]
GO
/****** Object:  Table [dbo].[PurchaseOrderHeadersV2_transit]    Script Date: 30/07/2025 12:27:44 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[PurchaseOrderHeadersV2_transit](
	[PurchaseOrderNumber] [varchar](255) NULL,
	[OrderVendorAccountNumber] [varchar](255) NULL,
	[AccountingDate] [varchar](255) NULL,
	[DeliveryAddressDescription] [varchar](255) NULL,
	[DefaultReceivingWarehouseId] [varchar](255) NULL,
	[DeliveryAddressStreet] [varchar](255) NULL,
	[DeliveryAddressCountryRegionId] [varchar](255) NULL,
	[DeliveryAddressCity] [varchar](255) NULL,
	[DocumentApprovalStatus] [varchar](255) NULL,
	[RequestedDeliveryDate] [varchar](255) NULL
) ON [PRIMARY]
GO
/****** Object:  Table [dbo].[PurchaseOrderHeadersV2_transit1]    Script Date: 30/07/2025 12:27:44 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[PurchaseOrderHeadersV2_transit1](
	[dataAreaId] [nvarchar](max) NULL,
	[PurchaseOrderNumber] [nvarchar](max) NULL,
	[ExpectedStoreAvailableSalesDate] [datetime2](0) NULL,
	[VendorInvoiceDeclarationId] [nvarchar](max) NULL,
	[DeliveryModeId] [nvarchar](max) NULL,
	[InvoiceAddressStreet] [nvarchar](max) NULL,
	[OrderVendorAccountNumber] [nvarchar](max) NULL,
	[Email] [nvarchar](max) NULL,
	[TransportationModeId] [nvarchar](max) NULL,
	[IsChangeManagementActive] [nvarchar](max) NULL,
	[AccountingDistributionTemplateName] [nvarchar](max) NULL,
	[DeliveryAddressDescription] [nvarchar](max) NULL,
	[VendorTransactionSettlementType] [nvarchar](max) NULL,
	[DeliveryCityInKana] [nvarchar](max) NULL,
	[DeliveryStreetInKana] [nvarchar](max) NULL,
	[ReasonComment] [nvarchar](max) NULL,
	[NumberSequenceGroupId] [nvarchar](max) NULL,
	[TransportationTemplateId] [nvarchar](max) NULL,
	[AccountingDate] [datetime2](0) NULL,
	[CashDiscountPercentage] [float] NULL,
	[PurchaseOrderName] [nvarchar](max) NULL,
	[RequestedDeliveryDate] [datetime2](0) NULL,
	[DeliveryAddressCountryRegionId] [nvarchar](max) NULL,
	[DeliveryAddressLatitude] [float] NULL,
	[MultilineDiscountVendorGroupCode] [nvarchar](max) NULL,
	[DeliveryAddressCity] [nvarchar](max) NULL,
	[ConfirmedDeliveryDate] [datetime2](0) NULL,
	[PurchaseRebateVendorGroupId] [nvarchar](max) NULL,
	[InvoiceAddressCounty] [nvarchar](max) NULL,
	[ChargeVendorGroupId] [nvarchar](max) NULL,
	[RequesterPersonnelNumber] [nvarchar](max) NULL,
	[ProjectId] [nvarchar](max) NULL,
	[ShippingCarrierId] [nvarchar](max) NULL,
	[TotalDiscountPercentage] [float] NULL,
	[DeliveryAddressDistrictName] [nvarchar](max) NULL,
	[PriceVendorGroupCode] [nvarchar](max) NULL,
	[PurchaseOrderHeaderCreationMethod] [nvarchar](max) NULL,
	[DeliveryAddressCountyId] [nvarchar](max) NULL,
	[DeliveryAddressZipCode] [nvarchar](max) NULL,
	[IsConsolidatedInvoiceTarget] [nvarchar](max) NULL,
	[ConfirmingPurchaseOrderCode] [nvarchar](max) NULL,
	[LanguageId] [nvarchar](max) NULL,
	[ReasonCode] [nvarchar](max) NULL,
	[DeliveryAddressDunsNumber] [nvarchar](max) NULL,
	[DeliveryTermsId] [nvarchar](max) NULL,
	[BankDocumentType] [nvarchar](max) NULL,
	[ExpectedStoreReceiptDate] [datetime2](0) NULL,
	[DeliveryAddressName] [nvarchar](max) NULL,
	[InvoiceAddressCountryRegionId] [nvarchar](max) NULL,
	[ReplenishmentServiceCategoryId] [nvarchar](max) NULL,
	[PurchaseOrderPoolId] [nvarchar](max) NULL,
	[DeliveryAddressStreetNumber] [nvarchar](max) NULL,
	[RequestedShipDate] [datetime2](0) NULL,
	[ExpectedCrossDockingDate] [datetime2](0) NULL,
	[InvoiceAddressStreetNumber] [nvarchar](max) NULL,
	[IsDeliveryAddressPrivate] [nvarchar](max) NULL,
	[TaxExemptNumber] [nvarchar](max) NULL,
	[FormattedInvoiceAddress] [nvarchar](max) NULL,
	[BuyerGroupId] [nvarchar](max) NULL,
	[DeliveryAddressCountryRegionISOCode] [nvarchar](max) NULL,
	[CashDiscountCode] [nvarchar](max) NULL,
	[PaymentScheduleName] [nvarchar](max) NULL,
	[IntrastatTransactionCode] [nvarchar](max) NULL,
	[URL] [nvarchar](max) NULL,
	[CurrencyCode] [nvarchar](max) NULL,
	[ConfirmingPurchaseOrderCodeLanguageId] [nvarchar](max) NULL,
	[InvoiceType] [nvarchar](max) NULL,
	[ArePricesIncludingSalesTax] [nvarchar](max) NULL,
	[DeliveryAddressLocationId] [nvarchar](max) NULL,
	[GSTSelfBilledInvoiceApprovalNumber] [nvarchar](max) NULL,
	[IsDeliveredDirectly] [nvarchar](max) NULL,
	[ConfirmedShipDate] [datetime2](0) NULL,
	[ShipCalendarId] [nvarchar](max) NULL,
	[IntrastatStatisticsProcedureCode] [nvarchar](max) NULL,
	[InvoiceVendorAccountNumber] [nvarchar](max) NULL,
	[OverrideSalesTax] [nvarchar](max) NULL,
	[DeliveryAddressStreet] [nvarchar](max) NULL,
	[VendorOrderReference] [nvarchar](max) NULL,
	[ReplenishmentWarehouseId] [nvarchar](max) NULL,
	[FixedDueDate] [datetime2](0) NULL,
	[TransportationDocumentLineId] [nvarchar](max) NULL,
	[SalesTaxGroupCode] [nvarchar](max) NULL,
	[IsDeliveryAddressOrderSpecific] [nvarchar](max) NULL,
	[VendorPostingProfileId] [nvarchar](max) NULL,
	[VendorPaymentMethodSpecificationName] [nvarchar](max) NULL,
	[InvoiceAddressCity] [nvarchar](max) NULL,
	[ShippingCarrierServiceGroupId] [nvarchar](max) NULL,
	[ContactPersonId] [nvarchar](max) NULL,
	[DefaultReceivingWarehouseId] [nvarchar](max) NULL,
	[EUSalesListCode] [nvarchar](max) NULL,
	[ImportDeclarationNumber] [nvarchar](max) NULL,
	[PurchaseOrderStatus] [nvarchar](max) NULL,
	[PaymentTermsName] [nvarchar](max) NULL,
	[DeliveryAddressLongitude] [float] NULL,
	[DocumentApprovalStatus] [nvarchar](max) NULL,
	[InvoiceAddressZipCode] [nvarchar](max) NULL,
	[ShippingCarrierServiceId] [nvarchar](max) NULL,
	[DefaultLedgerDimensionDisplayValue] [nvarchar](max) NULL,
	[DeliveryAddressTimeZone] [nvarchar](max) NULL,
	[AttentionInformation] [nvarchar](max) NULL,
	[DeliveryAddressStateId] [nvarchar](max) NULL,
	[DeliveryBuildingCompliment] [nvarchar](max) NULL,
	[IntrastatTransportModeCode] [nvarchar](max) NULL,
	[DeliveryAddressPostBox] [nvarchar](max) NULL,
	[IsOneTimeVendor] [nvarchar](max) NULL,
	[IntrastatPortId] [nvarchar](max) NULL,
	[OrdererPersonnelNumber] [nvarchar](max) NULL,
	[VendorPaymentMethodName] [nvarchar](max) NULL,
	[InvoiceAddressState] [nvarchar](max) NULL,
	[DefaultReceivingSiteId] [nvarchar](max) NULL,
	[LineDiscountVendorGroupCode] [nvarchar](max) NULL,
	[TransportationRoutePlanId] [nvarchar](max) NULL,
	[ZakatContractNumber] [nvarchar](max) NULL,
	[FormattedDeliveryAddress] [nvarchar](max) NULL,
	[TotalDiscountVendorGroupCode] [nvarchar](max) NULL,
	[TradeEndCustomerAccount] [nvarchar](max) NULL,
	[FiscalDocumentOperationTypeId] [nvarchar](max) NULL
) ON [PRIMARY] TEXTIMAGE_ON [PRIMARY]
GO
/****** Object:  Table [dbo].[PurchaseOrderLinesV2_1M]    Script Date: 30/07/2025 12:27:44 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[PurchaseOrderLinesV2_1M](
	[dataAreaId] [nvarchar](max) NULL,
	[PurchaseOrderNumber] [nvarchar](max) NULL,
	[LineNumber] [bigint] NULL,
	[ProcurementProductCategoryName] [nvarchar](max) NULL,
	[Tax1099SAddressOrLegalDescription] [nvarchar](max) NULL,
	[FixedAssetNumber] [nvarchar](max) NULL,
	[Tax1099GTaxYear] [bigint] NULL,
	[VendorRetentionTermRuleDescription] [nvarchar](max) NULL,
	[ProjectSalesUnitSymbol] [nvarchar](max) NULL,
	[OrderedPurchaseQuantity] [float] NULL,
	[FormattedDelveryAddress] [nvarchar](max) NULL,
	[ProjectCategoryId] [nvarchar](max) NULL,
	[AccountingDistributionTemplateName] [nvarchar](max) NULL,
	[ItemNumber] [nvarchar](max) NULL,
	[DeliveryAddressDescription] [nvarchar](max) NULL,
	[MultilineDiscountPercentage] [float] NULL,
	[PurchaseRequisitionId] [nvarchar](max) NULL,
	[DeliveryCityInKana] [nvarchar](max) NULL,
	[RetailProductVariantNumber] [nvarchar](max) NULL,
	[DeliveryStreetInKana] [nvarchar](max) NULL,
	[LineDiscountAmount] [float] NULL,
	[ProductStyleId] [nvarchar](max) NULL,
	[IsTax1099SPropertyOrServices] [nvarchar](max) NULL,
	[ProjectTaxGroupCode] [nvarchar](max) NULL,
	[ProjectTaxItemGroupCode] [nvarchar](max) NULL,
	[Barcode] [nvarchar](max) NULL,
	[IsNewFixedAsset] [nvarchar](max) NULL,
	[ProductConfigurationId] [nvarchar](max) NULL,
	[Tax1099GVendorStateId] [nvarchar](max) NULL,
	[WorkflowState] [nvarchar](max) NULL,
	[IsIntrastatTriangularDeal] [nvarchar](max) NULL,
	[Tax1099StateId] [nvarchar](max) NULL,
	[IsPartialDeliveryPrevented] [nvarchar](max) NULL,
	[MultilineDiscountAmount] [float] NULL,
	[Tax1099Type] [nvarchar](max) NULL,
	[RequestedDeliveryDate] [datetime2](0) NULL,
	[ItemBatchNumber] [nvarchar](max) NULL,
	[DeliveryAddressCountryRegionId] [nvarchar](max) NULL,
	[DeliveryAddressLatitude] [float] NULL,
	[ReceivingWarehouseId] [nvarchar](max) NULL,
	[DeliveryAddressCity] [nvarchar](max) NULL,
	[ConfirmedDeliveryDate] [datetime2](0) NULL,
	[PurchaseUnitSymbol] [nvarchar](max) NULL,
	[PurchaseRebateVendorGroupId] [nvarchar](max) NULL,
	[IsDeleted] [nvarchar](max) NULL,
	[RequesterPersonnelNumber] [nvarchar](max) NULL,
	[ProjectId] [nvarchar](max) NULL,
	[IsTax1099GTradeOrBusinessIncome] [nvarchar](max) NULL,
	[ProjectLinePropertyId] [nvarchar](max) NULL,
	[DeliveryAddressDistrictName] [nvarchar](max) NULL,
	[DeliveryAddressCountyId] [nvarchar](max) NULL,
	[Tax1099SBuyerPartOfRealEstateTaxAmount] [float] NULL,
	[ProductSizeId] [nvarchar](max) NULL,
	[FixedPriceCharges] [float] NULL,
	[DeliveryAddressZipCode] [nvarchar](max) NULL,
	[UnitWeight] [float] NULL,
	[Tax1099SClosingDate] [datetime2](0) NULL,
	[DeliveryAddressDunsNumber] [nvarchar](max) NULL,
	[IsAddedByChannel] [nvarchar](max) NULL,
	[PurchasePriceQuantity] [float] NULL,
	[ServiceFiscalInformationCode] [nvarchar](max) NULL,
	[DeliveryAddressName] [nvarchar](max) NULL,
	[Tax1099BoxId] [nvarchar](max) NULL,
	[BudgetReservationLineNumber] [bigint] NULL,
	[BOMId] [nvarchar](max) NULL,
	[FixedAssetTransactionType] [nvarchar](max) NULL,
	[DeliveryAddressStreetNumber] [nvarchar](max) NULL,
	[ReceivingWarehouseLocationId] [nvarchar](max) NULL,
	[NGPCode] [bigint] NULL,
	[IsDeliveryAddressPrivate] [nvarchar](max) NULL,
	[OriginStateId] [nvarchar](max) NULL,
	[ItemWithholdingTaxGroupCode] [nvarchar](max) NULL,
	[MainAccountIdDisplayValue] [nvarchar](max) NULL,
	[OrderedInventoryStatusId] [nvarchar](max) NULL,
	[CatchWeightUnitSymbol] [nvarchar](max) NULL,
	[DeliveryAddressCountryRegionISOCode] [nvarchar](max) NULL,
	[ItemSerialNumber] [nvarchar](max) NULL,
	[CalculateLineAmount] [nvarchar](max) NULL,
	[ReceivingSiteId] [nvarchar](max) NULL,
	[ProjectSalesCurrencyCode] [nvarchar](max) NULL,
	[IntrastatTransactionCode] [nvarchar](max) NULL,
	[DeliveryAddressLocationId] [nvarchar](max) NULL,
	[ProjectActivityNumber] [nvarchar](max) NULL,
	[SalesTaxItemGroupCode] [nvarchar](max) NULL,
	[RouteId] [nvarchar](max) NULL,
	[ProductVersionId] [nvarchar](max) NULL,
	[ShipCalendarId] [nvarchar](max) NULL,
	[Tax1099GStateTaxWithheldAmount] [float] NULL,
	[IntrastatStatisticsProcedureCode] [nvarchar](max) NULL,
	[OverrideSalesTax] [nvarchar](max) NULL,
	[LineDescription] [nvarchar](max) NULL,
	[GSTHSTTaxType] [nvarchar](max) NULL,
	[DeliveryAddressStreet] [nvarchar](max) NULL,
	[ConfirmedShippingDate] [datetime2](0) NULL,
	[CustomerReference] [nvarchar](max) NULL,
	[InventoryLotId] [nvarchar](max) NULL,
	[VendorRetentionTermRuleId] [nvarchar](max) NULL,
	[SalesTaxGroupCode] [nvarchar](max) NULL,
	[IsDeliveryAddressOrderSpecific] [nvarchar](max) NULL,
	[CustomerRequisitionNumber] [nvarchar](max) NULL,
	[PurchasePrice] [float] NULL,
	[PlanningPriority] [float] NULL,
	[WillProductReceivingCrossDockProducts] [nvarchar](max) NULL,
	[LineDiscountPercentage] [float] NULL,
	[DIOTOperationType] [nvarchar](max) NULL,
	[FixedAssetValueModelId] [nvarchar](max) NULL,
	[OrderedCatchWeightQuantity] [float] NULL,
	[ProjectWorkerPersonnelNumber] [nvarchar](max) NULL,
	[AllowedUnderdeliveryPercentage] [float] NULL,
	[AllowedOverdeliveryPercentage] [float] NULL,
	[DeliveryAddressLongitude] [float] NULL,
	[FixedAssetGroupId] [nvarchar](max) NULL,
	[PurchaseOrderLineStatus] [nvarchar](max) NULL,
	[IntrastatCommodityCode] [nvarchar](max) NULL,
	[DefaultLedgerDimensionDisplayValue] [nvarchar](max) NULL,
	[DeliveryAddressTimeZone] [nvarchar](max) NULL,
	[BudgetReservationDocumentNumber] [nvarchar](max) NULL,
	[ProductColorId] [nvarchar](max) NULL,
	[CFOPCode] [nvarchar](max) NULL,
	[DeliveryAddressStateId] [nvarchar](max) NULL,
	[DeliveryBuildingCompliment] [nvarchar](max) NULL,
	[IntrastatTransportModeCode] [nvarchar](max) NULL,
	[Tax1099StateAmount] [float] NULL,
	[DeliveryAddressPostBox] [nvarchar](max) NULL,
	[LineAmount] [float] NULL,
	[OriginCountryRegionId] [nvarchar](max) NULL,
	[IntrastatPortId] [nvarchar](max) NULL,
	[IntrastatSpecialMovementCode] [nvarchar](max) NULL,
	[Tax1099Amount] [float] NULL,
	[BarCodeSetupId] [nvarchar](max) NULL,
	[VendorInvoiceMatchingPolicy] [nvarchar](max) NULL,
	[Tax1099GVendorStateTaxId] [nvarchar](max) NULL,
	[ProjectSalesPrice] [float] NULL,
	[RequestedShippingDate] [datetime2](0) NULL,
	[PurchaseOrderLineCreationMethod] [nvarchar](max) NULL,
	[WithholdingTaxGroupCode] [nvarchar](max) NULL,
	[SkipCreateAutoCharges] [nvarchar](max) NULL,
	[ExternalItemNumber] [nvarchar](max) NULL,
	[IsProjectPayWhenPaid] [nvarchar](max) NULL,
	[IsLineStopped] [nvarchar](max) NULL,
	[IntrastatStatisticValue] [float] NULL,
	[DlvMode] [nvarchar](max) NULL,
	[DlvTerm] [nvarchar](max) NULL,
	[HSFOC] [nvarchar](max) NULL,
	[FinTagDisplayValue] [nvarchar](max) NULL
) ON [PRIMARY] TEXTIMAGE_ON [PRIMARY]
GO
/****** Object:  Table [dbo].[PurchasePriceAgreements]    Script Date: 30/07/2025 12:27:44 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[PurchasePriceAgreements](
	[ItemNumber] [int] NULL,
	[QuantityUnitSymbol] [varchar](255) NULL,
	[VendorAccountNumber] [varchar](255) NULL,
	[PriceApplicableFromDate] [varchar](255) NULL,
	[PriceApplicableToDate] [varchar](255) NULL,
	[Price] [float] NULL
) ON [PRIMARY]
GO
/****** Object:  Table [dbo].[PurchTableBiEntities]    Script Date: 30/07/2025 12:27:44 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[PurchTableBiEntities](
	[dataAreaId] [nvarchar](max) NULL,
	[PurchId] [nvarchar](max) NULL,
	[UnitedVATInvoice_LT] [nvarchar](max) NULL,
	[EXIMPorts_IN] [bigint] NULL,
	[DeliveryType] [nvarchar](max) NULL,
	[InterCompanySalesId] [nvarchar](max) NULL,
	[DocumentState] [nvarchar](max) NULL,
	[MatchingAgreement] [bigint] NULL,
	[DiscPercent] [float] NULL,
	[PurchName] [nvarchar](max) NULL,
	[NumberSequenceGroup] [nvarchar](max) NULL,
	[InvoiceAccount] [nvarchar](max) NULL,
	[IsEncumbranceRequired] [nvarchar](max) NULL,
	[ReturnItemNum] [nvarchar](max) NULL,
	[ReqAttention] [nvarchar](max) NULL,
	[PostingProfile] [nvarchar](max) NULL,
	[ConfirmedDlvEarliest] [datetime2](0) NULL,
	[Email] [nvarchar](max) NULL,
	[SysRecVersion] [bigint] NULL,
	[ReasonTableRef] [bigint] NULL,
	[VendGroup] [nvarchar](max) NULL,
	[InterCompanyOrigin] [nvarchar](max) NULL,
	[ServiceCategory] [nvarchar](max) NULL,
	[ItemBuyerGroupId] [nvarchar](max) NULL,
	[VATNum] [nvarchar](max) NULL,
	[ReturnReplacementCreated] [nvarchar](max) NULL,
	[SystemEntryChangePolicy] [bigint] NULL,
	[FSHAutoCreated] [nvarchar](max) NULL,
	[DocumentStatus] [nvarchar](max) NULL,
	[RetailDriverDetails] [nvarchar](max) NULL,
	[AccountingDate] [datetime2](0) NULL,
	[ContractNum_SA] [nvarchar](max) NULL,
	[Requester] [bigint] NULL,
	[SourceDocumentHeader] [bigint] NULL,
	[TAMVendRebateGroupId] [nvarchar](max) NULL,
	[ServiceAddress] [nvarchar](max) NULL,
	[AutoSummaryModuleType] [nvarchar](max) NULL,
	[CreatedOn] [datetime2](0) NULL,
	[Port] [nvarchar](max) NULL,
	[TransactionCode] [nvarchar](max) NULL,
	[OrderAccount] [nvarchar](max) NULL,
	[ServiceDate] [datetime2](0) NULL,
	[DlvTerm] [nvarchar](max) NULL,
	[VendorRef] [nvarchar](max) NULL,
	[ListCode] [nvarchar](max) NULL,
	[PurchaseOrderHeaderCreationMethod] [nvarchar](max) NULL,
	[PaymSpec] [nvarchar](max) NULL,
	[DeliveryDate] [datetime2](0) NULL,
	[MultiLineDisc] [nvarchar](max) NULL,
	[SysDataAreaId] [nvarchar](max) NULL,
	[InventSiteId] [nvarchar](max) NULL,
	[ManualEntryChangepolicy] [bigint] NULL,
	[FinalizeClosingDate] [datetime2](0) NULL,
	[LanguageId] [nvarchar](max) NULL,
	[FreightSlipType] [nvarchar](max) NULL,
	[BankDocumentType] [nvarchar](max) NULL,
	[InterCompanyOriginalCustAccount] [nvarchar](max) NULL,
	[VendInvoiceDeclaration_IS] [bigint] NULL,
	[Transport] [nvarchar](max) NULL,
	[WorkerPurchPlacer] [bigint] NULL,
	[OneTimeVendor] [nvarchar](max) NULL,
	[InterCompanyOrder] [nvarchar](max) NULL,
	[SourceKey] [bigint] NULL,
	[ReportingCurrencyFixedExchRate] [float] NULL,
	[IsModified] [nvarchar](max) NULL,
	[VATNumRecId] [bigint] NULL,
	[InterCompanyDirectDelivery] [nvarchar](max) NULL,
	[RetailRetailStatusType] [nvarchar](max) NULL,
	[PurchPoolId] [nvarchar](max) NULL,
	[CrossDockingDate] [datetime2](0) NULL,
	[InclTax] [nvarchar](max) NULL,
	[CountyOrigDest] [nvarchar](max) NULL,
	[FixedExchRate] [float] NULL,
	[LineDisc] [nvarchar](max) NULL,
	[InterCompanyAllowIndirectCreation] [nvarchar](max) NULL,
	[URL] [nvarchar](max) NULL,
	[VATNumTableType] [nvarchar](max) NULL,
	[CurrencyCode] [nvarchar](max) NULL,
	[InvoiceAutoNumbering_LT] [nvarchar](max) NULL,
	[InventLocationId] [nvarchar](max) NULL,
	[MCRDropShipment] [nvarchar](max) NULL,
	[PriceGroupId] [nvarchar](max) NULL,
	[CashDisc] [nvarchar](max) NULL,
	[TaxGroup] [nvarchar](max) NULL,
	[IntrastatAddValue_LV] [float] NULL,
	[CovStatus] [bigint] NULL,
	[StatProcId] [nvarchar](max) NULL,
	[ServiceName] [nvarchar](max) NULL,
	[BankCentralBankPurposeText] [nvarchar](max) NULL,
	[SysCreatedBy] [nvarchar](max) NULL,
	[OverrideSalesTax] [nvarchar](max) NULL,
	[BankCentralBankPurposeCode] [nvarchar](max) NULL,
	[CashDiscPercent] [float] NULL,
	[MarkupGroup] [nvarchar](max) NULL,
	[CXMLOrderEnable] [nvarchar](max) NULL,
	[DlvMode] [nvarchar](max) NULL,
	[ConfirmingPO] [bigint] NULL,
	[FixedDueDate] [datetime2](0) NULL,
	[LocalDeliveryDate] [datetime2](0) NULL,
	[DeliveryName] [nvarchar](max) NULL,
	[TradeEndCustomerAccount] [nvarchar](max) NULL,
	[AvailSalesDate] [datetime2](0) NULL,
	[OneTimeSupplier] [nvarchar](max) NULL,
	[IntrastatFulfillmentDate_HU] [datetime2](0) NULL,
	[DeliveryPostalAddress] [bigint] NULL,
	[AddressRefTableId] [bigint] NULL,
	[PurchOrderFormNum] [nvarchar](max) NULL,
	[ConfirmedDlv] [datetime2](0) NULL,
	[ContactPersonId] [nvarchar](max) NULL,
	[InterCompanyOriginalSalesId] [nvarchar](max) NULL,
	[EnterpriseNumber] [nvarchar](max) NULL,
	[InterCompanyCompanyId] [nvarchar](max) NULL,
	[AccountingDistributionTemplate] [bigint] NULL,
	[AddressRefRecId] [bigint] NULL,
	[PaymentSched] [nvarchar](max) NULL,
	[ExchangeRateDate] [datetime2](0) NULL,
	[IntentLetterId_IT] [nvarchar](max) NULL,
	[PaymMode] [nvarchar](max) NULL,
	[ReplenishmentLocation] [nvarchar](max) NULL,
	[FreightZone] [nvarchar](max) NULL,
	[SourceDocumentLine] [bigint] NULL,
	[BillToAddress] [bigint] NULL,
	[PurchStatus] [nvarchar](max) NULL,
	[InterCompanyCustPurchOrderFormNum] [nvarchar](max) NULL,
	[PurchaseType] [nvarchar](max) NULL,
	[Payment] [nvarchar](max) NULL,
	[ReturnReasonCodeId] [nvarchar](max) NULL,
	[SystemEntrySource] [nvarchar](max) NULL,
	[ChangeRequestRequired] [nvarchar](max) NULL,
	[TaxPeriodPaymentCode_PL] [nvarchar](max) NULL,
	[EndDisc] [nvarchar](max) NULL,
	[SettleVoucher] [nvarchar](max) NULL,
	[ConsTarget_JP] [nvarchar](max) NULL,
	[ProjId] [nvarchar](max) NULL,
	[TransportationDocument] [bigint] NULL
) ON [PRIMARY] TEXTIMAGE_ON [PRIMARY]
GO
/****** Object:  Table [dbo].[QueryExecutionLog]    Script Date: 30/07/2025 12:27:44 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[QueryExecutionLog](
	[LogID] [int] IDENTITY(1,1) NOT NULL,
	[QueryText] [nvarchar](max) NULL,
	[ExecutionDateTime] [datetime] NULL,
	[ResultMessage] [nvarchar](max) NULL,
	[RowsAffected] [int] NULL,
	[DurationMilliseconds] [int] NULL,
	[Duration] [nvarchar](max) NULL,
PRIMARY KEY CLUSTERED 
(
	[LogID] ASC
)WITH (PAD_INDEX = OFF, STATISTICS_NORECOMPUTE = OFF, IGNORE_DUP_KEY = OFF, ALLOW_ROW_LOCKS = ON, ALLOW_PAGE_LOCKS = ON, OPTIMIZE_FOR_SEQUENTIAL_KEY = OFF) ON [PRIMARY]
) ON [PRIMARY] TEXTIMAGE_ON [PRIMARY]
GO
/****** Object:  Table [dbo].[ReleasedDistinctProductsV2]    Script Date: 30/07/2025 12:27:44 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[ReleasedDistinctProductsV2](
	[dataAreaId] [nvarchar](max) NULL,
	[ItemNumber] [nvarchar](max) NULL,
	[IsPhantom] [nvarchar](max) NULL,
	[IsPurchasePriceIncludingCharges] [nvarchar](max) NULL,
	[ItemFiscalClassificationCode] [nvarchar](max) NULL,
	[MarginABCCode] [nvarchar](max) NULL,
	[IsICMSTaxAppliedOnService] [nvarchar](max) NULL,
	[ShippingAndReceivingSortOrderCode] [bigint] NULL,
	[ProductionConsumptionWidthConversionFactor] [float] NULL,
	[AlternativeProductSizeId] [nvarchar](max) NULL,
	[RawMaterialPickingPrinciple] [nvarchar](max) NULL,
	[ProductionConsumptionDepthConversionFactor] [float] NULL,
	[ItemModelGroupId] [nvarchar](max) NULL,
	[GrossProductHeight] [float] NULL,
	[AlternativeProductVersionId] [nvarchar](max) NULL,
	[IsSalesWithholdingTaxCalculated] [nvarchar](max) NULL,
	[ProductVolume] [float] NULL,
	[TrackingDimensionGroupName] [nvarchar](max) NULL,
	[PurchaseSalesTaxItemGroupCode] [nvarchar](max) NULL,
	[PlanningFormulaItemNumber] [nvarchar](max) NULL,
	[WarehouseMobileDeviceDescriptionLine1] [nvarchar](max) NULL,
	[WarehouseMobileDeviceDescriptionLine2] [nvarchar](max) NULL,
	[SalesItemWithholdingTaxGroupCode] [nvarchar](max) NULL,
	[IsPOSRegistrationQuantityNegative] [nvarchar](max) NULL,
	[UpperWarrantablePriceRangeLimit] [float] NULL,
	[POSRegistrationPlannedBlockedDate] [datetime2](0) NULL,
	[SellEndDate] [datetime2](0) NULL,
	[IsPurchaseWithholdingTaxCalculated] [nvarchar](max) NULL,
	[DefaultLedgerDimensionDisplayValue] [nvarchar](max) NULL,
	[WarrantyDurationTimeUnit] [nvarchar](max) NULL,
	[CommissionProductGroupId] [nvarchar](max) NULL,
	[IsExemptFromAutomaticNotificationAndCancellation] [nvarchar](max) NULL,
	[ProductionType] [nvarchar](max) NULL,
	[NetProductWeight] [float] NULL,
	[ProductionPoolId] [nvarchar](max) NULL,
	[SalesSupplementaryProductProductGroupId] [nvarchar](max) NULL,
	[WarrantablePriceRangeBaseType] [nvarchar](max) NULL,
	[StorageDimensionGroupName] [nvarchar](max) NULL,
	[PurchasePricingPrecision] [bigint] NULL,
	[BOMUnitSymbol] [nvarchar](max) NULL,
	[SalesPriceCalculationContributionRatio] [float] NULL,
	[CatchWeightUnitSymbol] [nvarchar](max) NULL,
	[VendorInvoiceLineMatchingPolicy] [nvarchar](max) NULL,
	[SellStartDate] [datetime2](0) NULL,
	[PhysicalDimensionGroupId] [nvarchar](max) NULL,
	[CarryingCostABCCode] [nvarchar](max) NULL,
	[CostCalculationBOMLevel] [bigint] NULL,
	[TransferOrderOverdeliveryPercentage] [float] NULL,
	[UnitConversionSequenceGroupId] [nvarchar](max) NULL,
	[WillPickingWorkbenchApplyBoxingLogic] [nvarchar](max) NULL,
	[FixedSalesPriceCharges] [float] NULL,
	[IsDeliveredDirectly] [nvarchar](max) NULL,
	[SalesGSTReliefCategoryCode] [nvarchar](max) NULL,
	[IsScaleProduct] [nvarchar](max) NULL,
	[AlternativeProductColorId] [nvarchar](max) NULL,
	[FixedPurchasePriceCharges] [float] NULL,
	[IsUnitCostIncludingCharges] [nvarchar](max) NULL,
	[ShipStartDate] [datetime2](0) NULL,
	[SalesPrice] [float] NULL,
	[SalesPriceCalculationModel] [nvarchar](max) NULL,
	[ArrivalHandlingTime] [bigint] NULL,
	[IntrastatCommodityCode] [nvarchar](max) NULL,
	[AreTransportationManagementProcessesEnabled] [nvarchar](max) NULL,
	[IsShipAloneEnabled] [nvarchar](max) NULL,
	[ProductionConsumptionDensityConversionFactor] [float] NULL,
	[PurchasePriceDate] [datetime2](0) NULL,
	[SalesPricingPrecision] [bigint] NULL,
	[PurchaseChargesQuantity] [float] NULL,
	[ProductSearchName] [nvarchar](max) NULL,
	[ValueABCCode] [nvarchar](max) NULL,
	[VariableScrapPercentage] [float] NULL,
	[UnitCostDate] [datetime2](0) NULL,
	[MaximumPickQuantity] [float] NULL,
	[AlternativeProductStyleId] [nvarchar](max) NULL,
	[BarcodeSetupId] [nvarchar](max) NULL,
	[IsSalesPriceIncludingCharges] [nvarchar](max) NULL,
	[PurchasePriceQuantity] [float] NULL,
	[PurchaseChargeProductGroupId] [nvarchar](max) NULL,
	[ContinuityScheduleId] [nvarchar](max) NULL,
	[FixedCostCharges] [float] NULL,
	[CostGroupId] [nvarchar](max) NULL,
	[SalesLineDiscountProductGroupCode] [nvarchar](max) NULL,
	[POSRegistrationActivationDate] [datetime2](0) NULL,
	[MaximumCatchWeightQuantity] [float] NULL,
	[ProductLifeCycleValidToDate] [datetime2](0) NULL,
	[WarrantyDurationTime] [bigint] NULL,
	[ServiceFiscalInformationCode] [nvarchar](max) NULL,
	[PurchaseSupplementaryProductProductGroupId] [nvarchar](max) NULL,
	[InventoryUnitSymbol] [nvarchar](max) NULL,
	[WillTotalPurchaseDiscountCalculationIncludeProduct] [nvarchar](max) NULL,
	[PackSizeCategoryId] [nvarchar](max) NULL,
	[SalesChargesQuantity] [float] NULL,
	[BatchMergeDateCalculationMethod] [nvarchar](max) NULL,
	[SalesMultilineDiscountProductGroupCode] [nvarchar](max) NULL,
	[PurchasePrice] [float] NULL,
	[SalesChargeProductGroupId] [nvarchar](max) NULL,
	[IsIntercompanyPurchaseUsageBlocked] [nvarchar](max) NULL,
	[AlternativeProductConfigurationId] [nvarchar](max) NULL,
	[SalesOverdeliveryPercentage] [float] NULL,
	[IsDiscountPOSRegistrationProhibited] [nvarchar](max) NULL,
	[BestBeforePeriodDays] [bigint] NULL,
	[PurchaseOverdeliveryPercentage] [float] NULL,
	[PurchaseUnitSymbol] [nvarchar](max) NULL,
	[SalesUnderdeliveryPercentage] [float] NULL,
	[BuyerGroupId] [nvarchar](max) NULL,
	[ServiceType] [nvarchar](max) NULL,
	[NecessaryProductionWorkingTimeSchedulingPropertyId] [nvarchar](max) NULL,
	[InventoryGSTReliefCategoryCode] [nvarchar](max) NULL,
	[ApprovedVendorCheckMethod] [nvarchar](max) NULL,
	[SalesRebateProductGroupId] [nvarchar](max) NULL,
	[InventoryReservationHierarchyName] [nvarchar](max) NULL,
	[FlushingPrinciple] [nvarchar](max) NULL,
	[SalesPriceQuantity] [float] NULL,
	[YieldPercentage] [float] NULL,
	[TareProductWeight] [float] NULL,
	[ApproximateSalesTaxPercentage] [float] NULL,
	[PackingDutyQuantity] [float] NULL,
	[PurchaseLineDiscountProductGroupCode] [nvarchar](max) NULL,
	[WillInventoryIssueAutomaticallyReportAsFinished] [nvarchar](max) NULL,
	[ProductFiscalInformationType] [nvarchar](max) NULL,
	[PackageHandlingTime] [bigint] NULL,
	[GrossProductWidth] [float] NULL,
	[ShelfLifePeriodDays] [bigint] NULL,
	[TransferOrderUnderdeliveryPercentage] [float] NULL,
	[DefaultReceivingQuantity] [float] NULL,
	[POSRegistrationBlockedDate] [datetime2](0) NULL,
	[MustKeyInCommentAtPOSRegister] [nvarchar](max) NULL,
	[ConstantScrapQuantity] [float] NULL,
	[PotencyBaseAttributeValueEntryEvent] [nvarchar](max) NULL,
	[KeyInPriceRequirementsAtPOSRegister] [nvarchar](max) NULL,
	[IntrastatChargePercentage] [float] NULL,
	[ProductCoverageGroupId] [nvarchar](max) NULL,
	[PotencyBaseAttibuteTargetValue] [float] NULL,
	[IsIntercompanySalesUsageBlocked] [nvarchar](max) NULL,
	[PackingMaterialGroupId] [nvarchar](max) NULL,
	[PurchaseRebateProductGroupId] [nvarchar](max) NULL,
	[PrimaryVendorAccountNumber] [nvarchar](max) NULL,
	[SearchName] [nvarchar](max) NULL,
	[ProductType] [nvarchar](max) NULL,
	[ProjectCategoryId] [nvarchar](max) NULL,
	[OriginCountryRegionId] [nvarchar](max) NULL,
	[AlternativeItemNumber] [nvarchar](max) NULL,
	[BOMLevel] [bigint] NULL,
	[PurchaseItemWithholdingTaxGroupCode] [nvarchar](max) NULL,
	[IsZeroPricePOSRegistrationAllowed] [nvarchar](max) NULL,
	[CostChargesQuantity] [float] NULL,
	[IsUnitCostAutomaticallyUpdated] [nvarchar](max) NULL,
	[DefaultDirectDeliveryWarehouse] [nvarchar](max) NULL,
	[ProductTaxationOrigin] [nvarchar](max) NULL,
	[IsVariantShelfLabelsPrintingEnabled] [nvarchar](max) NULL,
	[UnitCost] [float] NULL,
	[AlternativeProductUsageCondition] [nvarchar](max) NULL,
	[SalesPriceDate] [datetime2](0) NULL,
	[WillTotalSalesDiscountCalculationIncludeProduct] [nvarchar](max) NULL,
	[PurchasePriceToleranceGroupId] [nvarchar](max) NULL,
	[IsInstallmentEligible] [nvarchar](max) NULL,
	[BaseSalesPriceSource] [nvarchar](max) NULL,
	[SerialNumberGroupCode] [nvarchar](max) NULL,
	[ProductLifeCycleValidFromDate] [datetime2](0) NULL,
	[ItemFiscalClassificationExceptionCode] [nvarchar](max) NULL,
	[NGPCode] [bigint] NULL,
	[SalesUnitSymbol] [nvarchar](max) NULL,
	[LowerWarrantablePriceRangeLimit] [float] NULL,
	[KeyInQuantityRequirementsAtPOSRegister] [nvarchar](max) NULL,
	[ProductionGroupId] [nvarchar](max) NULL,
	[DefaultOrderType] [nvarchar](max) NULL,
	[ProductGroupId] [nvarchar](max) NULL,
	[ProductionConsumptionHeightConversionFactor] [float] NULL,
	[ContinuityEventDuration] [bigint] NULL,
	[IsPOSRegistrationBlocked] [nvarchar](max) NULL,
	[BatchNumberGroupCode] [nvarchar](max) NULL,
	[PurchaseUnderdeliveryPercentage] [float] NULL,
	[GrossDepth] [float] NULL,
	[RevenueABCCode] [nvarchar](max) NULL,
	[PackageClassId] [nvarchar](max) NULL,
	[PurchaseGSTReliefCategoryCode] [nvarchar](max) NULL,
	[SalesPriceCalculationChargesPercentage] [float] NULL,
	[PurchaseMultilineDiscountProductGroupCode] [nvarchar](max) NULL,
	[WillWorkCenterPickingAllowNegativeInventory] [nvarchar](max) NULL,
	[ProductLifeCycleSeasonCode] [nvarchar](max) NULL,
	[SalesSalesTaxItemGroupCode] [nvarchar](max) NULL,
	[IsRestrictedForCoupons] [nvarchar](max) NULL,
	[IsSalesPriceAdjustmentAllowed] [nvarchar](max) NULL,
	[IsPurchasePriceAutomaticallyUpdated] [nvarchar](max) NULL,
	[MinimumCatchWeightQuantity] [float] NULL,
	[WillInventoryReceiptIgnoreFlushingPrinciple] [nvarchar](max) NULL,
	[ProductNumber] [nvarchar](max) NULL,
	[UnitCostQuantity] [float] NULL,
	[FreightAllocationGroupId] [nvarchar](max) NULL,
	[ComparisonPriceBaseUnitSymbol] [nvarchar](max) NULL,
	[CostCalculationGroupId] [nvarchar](max) NULL,
	[ShelfAdvicePeriodDays] [bigint] NULL,
	[OriginStateId] [nvarchar](max) NULL
) ON [PRIMARY] TEXTIMAGE_ON [PRIMARY]
GO
/****** Object:  Table [dbo].[ReleasedProductCreationsV2_bkup]    Script Date: 30/07/2025 12:27:44 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[ReleasedProductCreationsV2_bkup](
	[dataAreaId] [nvarchar](max) NULL,
	[ItemNumber] [nvarchar](max) NULL,
	[PurchaseUnitSymbol] [nvarchar](max) NULL,
	[ProductGroupId] [nvarchar](max) NULL,
	[ProductType] [nvarchar](max) NULL,
	[WarrantyDurationTime] [bigint] NULL,
	[InventoryUnitSymbol] [nvarchar](max) NULL,
	[WarrantablePriceRangeBaseType] [nvarchar](max) NULL,
	[UpperWarrantablePriceRangeLimit] [float] NULL,
	[RetailProductCategoryname] [nvarchar](max) NULL,
	[InventoryReservationHierarchyName] [nvarchar](max) NULL,
	[StorageDimensionGroupName] [nvarchar](max) NULL,
	[ProductNumber] [nvarchar](max) NULL,
	[ProductSubType] [nvarchar](max) NULL,
	[BOMUnitSymbol] [nvarchar](max) NULL,
	[SearchName] [nvarchar](max) NULL,
	[ServiceType] [nvarchar](max) NULL,
	[WarrantyDurationTimeUnit] [nvarchar](max) NULL,
	[VariantConfigurationTechnology] [nvarchar](max) NULL,
	[ProductDimensionGroupName] [nvarchar](max) NULL,
	[IsProductKit] [nvarchar](max) NULL,
	[SalesSalesTaxItemGroupCode] [nvarchar](max) NULL,
	[SalesUnitSymbol] [nvarchar](max) NULL,
	[IsCatchWeightProduct] [nvarchar](max) NULL,
	[ProductDescription] [nvarchar](max) NULL,
	[LowerWarrantablePriceRangeLimit] [float] NULL,
	[TrackingDimensionGroupName] [nvarchar](max) NULL,
	[ProductSearchName] [nvarchar](max) NULL,
	[PurchaseSalesTaxItemGroupCode] [nvarchar](max) NULL,
	[ProductName] [nvarchar](max) NULL,
	[ItemModelGroupId] [nvarchar](max) NULL
) ON [PRIMARY] TEXTIMAGE_ON [PRIMARY]
GO
/****** Object:  Table [dbo].[ReleasedProductCreationsV2_transit]    Script Date: 30/07/2025 12:27:44 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[ReleasedProductCreationsV2_transit](
	[ItemNumber] [int] NULL,
	[ProductGroupId] [varchar](255) NULL,
	[ProductType] [varchar](255) NULL,
	[InventoryUnitSymbol] [varchar](255) NULL,
	[RetailProductCategoryname] [varchar](255) NULL,
	[ProductNumber] [int] NULL,
	[BOMUnitSymbol] [varchar](255) NULL,
	[SalesSalesTaxItemGroupCode] [varchar](255) NULL,
	[PurchaseSalesTaxItemGroupCode] [varchar](255) NULL,
	[ProductName] [varchar](255) NULL
) ON [PRIMARY]
GO
/****** Object:  Table [dbo].[REORDER_branch_order]    Script Date: 30/07/2025 12:27:44 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[REORDER_branch_order](
	[ItemNumber] [nvarchar](max) NULL,
	[ProductName] [nvarchar](max) NULL,
	[ProductGroupId] [nvarchar](max) NULL,
	[RetailProductCategoryname] [nvarchar](max) NULL,
	[SalesSalesTaxItemGroupCode] [nvarchar](max) NULL,
	[Drug_id] [varchar](50) NULL,
	[STORECODE] [varchar](50) NULL,
	[LocationID] [varchar](50) NULL,
	[ShortName] [varchar](50) NULL,
	[Min] [int] NULL,
	[Max] [int] NULL,
	[Cost] [varchar](50) NULL,
	[Price] [varchar](50) NULL,
	[Vendor] [varchar](50) NULL,
	[Stock] [numeric](38, 0) NOT NULL,
	[Pending_Stock] [numeric](38, 2) NOT NULL,
	[Order] [int] NULL,
	[CONS] [money] NOT NULL,
	[Order_Group] [varchar](254) NULL,
	[turn] [bigint] NULL,
	[Store_Stock] [numeric](38, 2) NOT NULL
) ON [PRIMARY] TEXTIMAGE_ON [PRIMARY]
GO
/****** Object:  Table [dbo].[REORDER_branch_order_pass_1]    Script Date: 30/07/2025 12:27:44 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[REORDER_branch_order_pass_1](
	[ItemNumber] [nvarchar](max) NULL,
	[ProductName] [nvarchar](max) NULL,
	[STORECODE] [varchar](50) NULL,
	[LocationID] [varchar](50) NULL,
	[ShortName] [varchar](50) NULL,
	[Min] [int] NULL,
	[Max] [int] NULL,
	[Order] [int] NULL,
	[Turn] [int] NULL,
	[Store_Stock] [int] NULL,
	[taken] [int] NULL,
	[Running_Stock] [int] NULL,
	[Category] [varchar](50) NULL,
	[Stock] [float] NULL,
	[Unposted_Qty] [float] NULL,
	[Cost] [float] NULL,
	[Stock_after_Unposted] [float] NULL
) ON [PRIMARY] TEXTIMAGE_ON [PRIMARY]
GO
/****** Object:  Table [dbo].[REORDER_branch_order_pass_1_br_Zero]    Script Date: 30/07/2025 12:27:44 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[REORDER_branch_order_pass_1_br_Zero](
	[ItemNumber] [nvarchar](max) NULL,
	[ProductName] [nvarchar](max) NULL,
	[STORECODE] [varchar](50) NULL,
	[LocationID] [varchar](50) NULL,
	[ShortName] [varchar](50) NULL,
	[Min] [int] NULL,
	[Max] [int] NULL,
	[Order] [int] NULL,
	[Turn] [int] NULL,
	[Store_Stock] [int] NULL,
	[taken] [int] NULL,
	[Running_Stock] [int] NULL,
	[Category] [varchar](50) NULL,
	[Stock] [float] NULL,
	[Unposted_Qty] [float] NULL,
	[Cost] [float] NULL,
	[Stock_after_Unposted] [float] NULL
) ON [PRIMARY] TEXTIMAGE_ON [PRIMARY]
GO
/****** Object:  Table [dbo].[REORDER_branch_order_pass_1_max]    Script Date: 30/07/2025 12:27:44 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[REORDER_branch_order_pass_1_max](
	[ItemNumber] [nvarchar](max) NULL,
	[ProductName] [nvarchar](max) NULL,
	[STORECODE] [varchar](50) NULL,
	[LocationID] [varchar](50) NULL,
	[ShortName] [varchar](50) NULL,
	[Min] [int] NULL,
	[Max] [int] NULL,
	[Order] [int] NULL,
	[Turn] [int] NULL,
	[Store_Stock] [int] NULL,
	[taken] [int] NULL,
	[Running_Stock] [int] NULL,
	[Category] [varchar](50) NULL,
	[Stock] [float] NULL,
	[Unposted_Qty] [float] NULL,
	[Cost] [float] NULL,
	[Stock_after_Unposted] [float] NULL
) ON [PRIMARY] TEXTIMAGE_ON [PRIMARY]
GO
/****** Object:  Table [dbo].[REORDER_branch_order_pass_800_1]    Script Date: 30/07/2025 12:27:44 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[REORDER_branch_order_pass_800_1](
	[ItemNumber] [nvarchar](max) NULL,
	[ProductName] [nvarchar](max) NULL,
	[STORECODE] [varchar](50) NULL,
	[LocationID] [varchar](50) NULL,
	[ShortName] [varchar](50) NULL,
	[Min] [int] NULL,
	[Max] [int] NULL,
	[Order] [int] NULL,
	[Turn] [int] NULL,
	[Store_Stock] [int] NULL,
	[taken] [int] NULL,
	[Running_Stock] [int] NULL,
	[Category] [varchar](50) NULL,
	[Stock] [float] NULL,
	[Cost] [float] NULL,
	[Stock_after_Unposted] [float] NULL,
	[Qty_Unposted] [float] NULL
) ON [PRIMARY] TEXTIMAGE_ON [PRIMARY]
GO
/****** Object:  Table [dbo].[REORDER_branch_order_pass_800_1_br_zero]    Script Date: 30/07/2025 12:27:44 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[REORDER_branch_order_pass_800_1_br_zero](
	[ItemNumber] [nvarchar](max) NULL,
	[ProductName] [nvarchar](max) NULL,
	[STORECODE] [varchar](50) NULL,
	[LocationID] [varchar](50) NULL,
	[ShortName] [varchar](50) NULL,
	[Min] [int] NULL,
	[Max] [int] NULL,
	[Order] [int] NULL,
	[Turn] [int] NULL,
	[Store_Stock] [int] NULL,
	[taken] [int] NULL,
	[Running_Stock] [int] NULL,
	[Category] [varchar](50) NULL,
	[Stock] [float] NULL,
	[Cost] [float] NULL,
	[Stock_after_Unposted] [float] NULL,
	[Qty_Unposted] [float] NULL
) ON [PRIMARY] TEXTIMAGE_ON [PRIMARY]
GO
/****** Object:  Table [dbo].[RetailDiscounts]    Script Date: 30/07/2025 12:27:44 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[RetailDiscounts](
	[dataAreaId] [nvarchar](max) NULL,
	[OfferId] [nvarchar](max) NULL,
	[ProcessingStatus] [nvarchar](max) NULL,
	[Name] [nvarchar](max) NULL,
	[MixAndMatchDiscountType] [nvarchar](max) NULL,
	[IsDiscountCodeRequired] [nvarchar](max) NULL,
	[OfferQuantityLimit] [bigint] NULL,
	[MixAndMatchNoOfLeastExpensiveLines] [bigint] NULL,
	[Status] [nvarchar](max) NULL,
	[BarCode] [nvarchar](max) NULL,
	[Disclaimer] [nvarchar](max) NULL,
	[ThresholdCountNonDiscountItems] [nvarchar](max) NULL,
	[DisabledSince] [datetime2](0) NULL,
	[MultibuyDiscountType] [nvarchar](max) NULL,
	[Description] [nvarchar](max) NULL,
	[MixAndMatchDiscountAmount] [float] NULL,
	[ValidationPeriodId] [nvarchar](max) NULL,
	[DiscountRecordId] [bigint] NULL,
	[DiscountPercentValue] [float] NULL,
	[CurrencyCode] [nvarchar](max) NULL,
	[PricingPriorityNumber] [bigint] NULL,
	[ConcurrencyMode] [nvarchar](max) NULL,
	[DateValidationType] [nvarchar](max) NULL,
	[MixAndMatchDealPrice] [float] NULL,
	[DiscountCode] [nvarchar](max) NULL,
	[PrintDescriptionOnFiscalReceipt] [nvarchar](max) NULL,
	[ValidTo] [datetime2](0) NULL,
	[DiscountLedgerDimensionDisplayValue] [nvarchar](max) NULL,
	[ValidFrom] [datetime2](0) NULL,
	[MixAndMatchLeastExpensiveMode] [nvarchar](max) NULL,
	[MatchAllAssociatedPriceGroups] [nvarchar](max) NULL,
	[PeriodicDiscountType] [nvarchar](max) NULL
) ON [PRIMARY] TEXTIMAGE_ON [PRIMARY]
GO
/****** Object:  Table [dbo].[RetailEodStatementAggregations]    Script Date: 30/07/2025 12:27:44 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[RetailEodStatementAggregations](
	[dataAreaId] [nvarchar](max) NULL,
	[StatementId] [nvarchar](max) NULL,
	[Aggregation] [bigint] NULL,
	[InvoiceId] [nvarchar](max) NULL,
	[SalesId] [nvarchar](max) NULL,
	[StatementStatus] [nvarchar](max) NULL,
	[StoreNumber] [nvarchar](max) NULL,
	[ErrorMessage] [nvarchar](max) NULL,
	[AggregationStatus] [nvarchar](max) NULL
) ON [PRIMARY] TEXTIMAGE_ON [PRIMARY]
GO
/****** Object:  Table [dbo].[RetailMixAndMatchLineGroupSetups]    Script Date: 30/07/2025 12:27:44 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[RetailMixAndMatchLineGroupSetups](
	[dataAreaId] [nvarchar](max) NULL,
	[mixAndMatchLineGroup] [nvarchar](max) NULL,
	[discountLineColorId] [bigint] NULL,
	[numberOfItemsNeeded] [bigint] NULL
) ON [PRIMARY] TEXTIMAGE_ON [PRIMARY]
GO
/****** Object:  Table [dbo].[RetailTransactionHeaders]    Script Date: 30/07/2025 12:27:44 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[RetailTransactionHeaders](
	[dataAreaId] [nvarchar](max) NULL,
	[OMOperatingUnit_PartyNumber] [nvarchar](max) NULL,
	[ReplicationCounterFromOrigin] [bigint] NULL,
	[store] [nvarchar](max) NULL,
	[terminal] [nvarchar](max) NULL,
	[transactionId] [nvarchar](max) NULL,
	[COPAYGROSSNET] [bigint] NULL,
	[CustomerDOB] [datetime2](0) NULL,
	[TPANAME] [nvarchar](max) NULL,
	[OldMemberID] [nvarchar](max) NULL,
	[TpaCode] [nvarchar](max) NULL,
	[DoctorCode] [nvarchar](max) NULL,
	[NetAmount] [float] NULL,
	[LiveSubmissionId] [nvarchar](max) NULL,
	[INSURANCETRANS] [bigint] NULL,
	[COPAYTPANAME] [nvarchar](max) NULL,
	[LiveClaimsApproval] [nvarchar](max) NULL,
	[StartDateTime] [datetime2](0) NULL,
	[GrossAmount] [float] NULL,
	[ErxNo] [bigint] NULL,
	[SubmissionCount] [bigint] NULL,
	[CoPayAmount] [float] NULL,
	[InsCompanyCode] [nvarchar](max) NULL,
	[EmiratesId] [nvarchar](max) NULL,
	[COPAYLINE] [bigint] NULL,
	[AxInvoiceId] [nvarchar](max) NULL,
	[ApprovalCode] [nvarchar](max) NULL,
	[Remark] [nvarchar](max) NULL,
	[INSCOMPANYNAME] [nvarchar](max) NULL,
	[invoiceId] [nvarchar](max) NULL,
	[CustomerCode] [nvarchar](max) NULL,
	[PriorAuthorizationId] [nvarchar](max) NULL,
	[SettledAmount] [float] NULL,
	[INVOICEDOCNO] [nvarchar](max) NULL,
	[PBMTYPE] [bigint] NULL,
	[SUBMISSIONCOUNTER] [bigint] NULL,
	[TransDate] [datetime2](0) NULL,
	[ClinicianCode] [nvarchar](max) NULL,
	[HSRXHEALTHAUTHORITY] [nvarchar](max) NULL,
	[Type] [nvarchar](max) NULL,
	[DenialCode] [nvarchar](max) NULL,
	[RESUBMISSIONREASONCODE] [nvarchar](max) NULL,
	[CustomerWeight] [float] NULL,
	[coPayTpaCode] [nvarchar](max) NULL,
	[StoreEmpanelmentId] [nvarchar](max) NULL,
	[MemberId] [nvarchar](max) NULL,
	[PackageCode] [nvarchar](max) NULL,
	[TestClaimsApproval] [nvarchar](max) NULL,
	[Status] [nvarchar](max) NULL,
	[OldEmiratesID] [nvarchar](max) NULL,
	[TestSubmissionId] [nvarchar](max) NULL,
	[SALERETURN] [nvarchar](max) NULL,
	[CUSTOMERNAME] [nvarchar](max) NULL,
	[EXTERNALERXREF] [nvarchar](max) NULL,
	[CreatedOn] [datetime2](0) NULL,
	[ManualApproval] [nvarchar](max) NULL,
	[Network] [nvarchar](max) NULL
) ON [PRIMARY] TEXTIMAGE_ON [PRIMARY]
GO
/****** Object:  Table [dbo].[RetailTransactionSalesLines]    Script Date: 30/07/2025 12:27:44 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[RetailTransactionSalesLines](
	[dataAreaId] [nvarchar](max) NULL,
	[Terminal] [nvarchar](max) NULL,
	[TransactionNumber] [nvarchar](max) NULL,
	[LineNumber] [float] NULL,
	[OperatingUnitNumber] [nvarchar](max) NULL,
	[CustomerDiscount] [float] NULL,
	[RequestedReceiptDate] [datetime2](0) NULL,
	[CashDiscountAmount] [float] NULL,
	[TransactionDate] [datetime2](0) NULL,
	[LogisticsPostalAddressValidFrom] [datetime2](0) NULL,
	[OriginalItemSalesTaxGroup] [nvarchar](max) NULL,
	[SiteId] [nvarchar](max) NULL,
	[RetailEmailAddressContent] [nvarchar](max) NULL,
	[ItemSize] [nvarchar](max) NULL,
	[ModeOfDelivery] [nvarchar](max) NULL,
	[SkipReports] [nvarchar](max) NULL,
	[Warehouse] [nvarchar](max) NULL,
	[Exempt] [nvarchar](max) NULL,
	[PickupStartTime] [bigint] NULL,
	[TotalDiscount] [float] NULL,
	[TaxExemptPriceInclusiveOriginalPrice] [float] NULL,
	[IsLinkedProductNotOriginal] [nvarchar](max) NULL,
	[DiscountAmountWithoutTax] [float] NULL,
	[NetPrice] [float] NULL,
	[TaxRatePercent] [float] NULL,
	[PriceGroups] [nvarchar](max) NULL,
	[RFIDTagId] [nvarchar](max) NULL,
	[VariantNumber] [nvarchar](max) NULL,
	[CategoryHierarchyName] [nvarchar](max) NULL,
	[NonGST] [nvarchar](max) NULL,
	[TransactionCode] [nvarchar](max) NULL,
	[TotalDiscountPercentage] [float] NULL,
	[GiftCardOperation] [nvarchar](max) NULL,
	[Unit] [nvarchar](max) NULL,
	[TaxExemptPriceInclusiveReductionAmount] [float] NULL,
	[PriceInBarCode] [nvarchar](max) NULL,
	[LotID] [nvarchar](max) NULL,
	[ReturnQuantity] [float] NULL,
	[CustomerAccount] [nvarchar](max) NULL,
	[OriginalPrice] [float] NULL,
	[ItemRelation] [nvarchar](max) NULL,
	[RequestedShipDate] [datetime2](0) NULL,
	[TransactionStatus] [nvarchar](max) NULL,
	[ItemConfigId] [nvarchar](max) NULL,
	[Currency] [nvarchar](max) NULL,
	[ReturnOperatingUnitNumber] [nvarchar](max) NULL,
	[TaxRateType] [nvarchar](max) NULL,
	[LineDiscount] [float] NULL,
	[NetAmountInclusiveTax] [float] NULL,
	[InventoryStatus] [nvarchar](max) NULL,
	[LineManualDiscountPercentage] [float] NULL,
	[GiftCard] [nvarchar](max) NULL,
	[ChannelListingID] [nvarchar](max) NULL,
	[NetAmount] [float] NULL,
	[ItemColor] [nvarchar](max) NULL,
	[TenderDiscountPercentage] [float] NULL,
	[IsPriceChange] [nvarchar](max) NULL,
	[BarCode] [nvarchar](max) NULL,
	[UnitQuantity] [float] NULL,
	[LineManualDiscountAmount] [float] NULL,
	[StandardNetPrice] [float] NULL,
	[BusinessDate] [datetime2](0) NULL,
	[ReturnTerminal] [nvarchar](max) NULL,
	[IsWeightProduct] [nvarchar](max) NULL,
	[LogisticLocationId] [nvarchar](max) NULL,
	[IsScaleProduct] [nvarchar](max) NULL,
	[IsOriginalOfLinkedProductList] [nvarchar](max) NULL,
	[ItemStyle] [nvarchar](max) NULL,
	[ReceiptNumber] [nvarchar](max) NULL,
	[LinePercentageDiscount] [float] NULL,
	[ReasonCodeDiscount] [float] NULL,
	[CategoryName] [nvarchar](max) NULL,
	[TotalDiscountInfoCodeLineNum] [float] NULL,
	[KeyboardProductEntry] [nvarchar](max) NULL,
	[CancelledTransactionNumber] [nvarchar](max) NULL,
	[IsReturnNoSale] [nvarchar](max) NULL,
	[ElectronicDeliveryEmail] [nvarchar](max) NULL,
	[ItemId] [nvarchar](max) NULL,
	[HSNCode] [nvarchar](max) NULL,
	[SalesTaxAmount] [float] NULL,
	[ReturnTransactionNumber] [nvarchar](max) NULL,
	[Quantity] [float] NULL,
	[ServiceAccountingCode] [nvarchar](max) NULL,
	[Price] [float] NULL,
	[UnitPrice] [float] NULL,
	[SalesTaxGroup] [nvarchar](max) NULL,
	[OriginalSalesTaxGroup] [nvarchar](max) NULL,
	[IsLineDiscounted] [nvarchar](max) NULL,
	[ShelfNumber] [nvarchar](max) NULL,
	[ItemSalesTaxGroup] [nvarchar](max) NULL,
	[GiftCardType] [nvarchar](max) NULL,
	[SerialNumber] [nvarchar](max) NULL,
	[OfferNumber] [nvarchar](max) NULL,
	[CostAmount] [float] NULL,
	[SectionNumber] [nvarchar](max) NULL,
	[IsWeightManuallyEntered] [nvarchar](max) NULL,
	[DiscountAmountForPrinting] [float] NULL,
	[CustomerInvoiceDiscountAmount] [float] NULL,
	[ProductScanned] [nvarchar](max) NULL,
	[PeriodicDiscountPercentage] [float] NULL,
	[TenderDiscountAmount] [float] NULL,
	[ReturnTrackingStatus] [nvarchar](max) NULL,
	[ReturnLineNumber] [float] NULL,
	[PeriodicDiscountAmount] [float] NULL,
	[PeriodicDiscountGroup] [nvarchar](max) NULL,
	[PickupEndTime] [bigint] NULL
) ON [PRIMARY] TEXTIMAGE_ON [PRIMARY]
GO
/****** Object:  Table [dbo].[RetailTransactionSalesLinesV2]    Script Date: 30/07/2025 12:27:44 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[RetailTransactionSalesLinesV2](
	[dataAreaId] [nvarchar](max) NULL,
	[Terminal] [nvarchar](max) NULL,
	[TransactionNumber] [nvarchar](max) NULL,
	[LineNumber] [float] NULL,
	[OperatingUnitNumber] [nvarchar](max) NULL,
	[CustomerDiscount] [float] NULL,
	[RequestedReceiptDate] [datetime2](0) NULL,
	[CashDiscountAmount] [float] NULL,
	[TransactionDate] [datetime2](0) NULL,
	[LogisticsPostalAddressValidFrom] [datetime2](0) NULL,
	[OriginalItemSalesTaxGroup] [nvarchar](max) NULL,
	[SiteId] [nvarchar](max) NULL,
	[RetailEmailAddressContent] [nvarchar](max) NULL,
	[ItemSize] [nvarchar](max) NULL,
	[ModeOfDelivery] [nvarchar](max) NULL,
	[SkipReports] [nvarchar](max) NULL,
	[Warehouse] [nvarchar](max) NULL,
	[PickupStartTime] [bigint] NULL,
	[TotalDiscount] [float] NULL,
	[TaxExemptPriceInclusiveOriginalPrice] [float] NULL,
	[IsLinkedProductNotOriginal] [nvarchar](max) NULL,
	[DiscountAmountWithoutTax] [float] NULL,
	[NetPrice] [float] NULL,
	[PriceGroups] [nvarchar](max) NULL,
	[RFIDTagId] [nvarchar](max) NULL,
	[VariantNumber] [nvarchar](max) NULL,
	[CategoryHierarchyName] [nvarchar](max) NULL,
	[TransactionCode] [nvarchar](max) NULL,
	[TotalDiscountPercentage] [float] NULL,
	[FixedPriceCharges] [float] NULL,
	[Unit] [nvarchar](max) NULL,
	[TaxExemptPriceInclusiveReductionAmount] [float] NULL,
	[PriceInBarCode] [nvarchar](max) NULL,
	[LotID] [nvarchar](max) NULL,
	[ReturnQuantity] [float] NULL,
	[CustomerAccount] [nvarchar](max) NULL,
	[OriginalPrice] [float] NULL,
	[ItemRelation] [nvarchar](max) NULL,
	[RequestedShipDate] [datetime2](0) NULL,
	[TransactionStatus] [nvarchar](max) NULL,
	[ItemConfigId] [nvarchar](max) NULL,
	[Currency] [nvarchar](max) NULL,
	[ReturnOperatingUnitNumber] [nvarchar](max) NULL,
	[LineDiscount] [float] NULL,
	[NetAmountInclusiveTax] [float] NULL,
	[InventoryStatus] [nvarchar](max) NULL,
	[LineManualDiscountPercentage] [float] NULL,
	[GiftCard] [nvarchar](max) NULL,
	[ChannelListingID] [nvarchar](max) NULL,
	[NetAmount] [float] NULL,
	[ItemColor] [nvarchar](max) NULL,
	[IsPriceChange] [nvarchar](max) NULL,
	[BarCode] [nvarchar](max) NULL,
	[UnitQuantity] [float] NULL,
	[LineManualDiscountAmount] [float] NULL,
	[StandardNetPrice] [float] NULL,
	[BusinessDate] [datetime2](0) NULL,
	[ItemVersion] [nvarchar](max) NULL,
	[ReturnTerminal] [nvarchar](max) NULL,
	[IsWeightProduct] [nvarchar](max) NULL,
	[LogisticLocationId] [nvarchar](max) NULL,
	[IsScaleProduct] [nvarchar](max) NULL,
	[IsOriginalOfLinkedProductList] [nvarchar](max) NULL,
	[ItemStyle] [nvarchar](max) NULL,
	[ReceiptNumber] [nvarchar](max) NULL,
	[LinePercentageDiscount] [float] NULL,
	[ReasonCodeDiscount] [float] NULL,
	[CategoryName] [nvarchar](max) NULL,
	[TotalDiscountInfoCodeLineNum] [float] NULL,
	[KeyboardProductEntry] [nvarchar](max) NULL,
	[CancelledTransactionNumber] [nvarchar](max) NULL,
	[IsReturnNoSale] [nvarchar](max) NULL,
	[ElectronicDeliveryEmail] [nvarchar](max) NULL,
	[ItemId] [nvarchar](max) NULL,
	[SalesTaxAmount] [float] NULL,
	[ReturnTransactionNumber] [nvarchar](max) NULL,
	[Quantity] [float] NULL,
	[Price] [float] NULL,
	[UnitPrice] [float] NULL,
	[SalesTaxGroup] [nvarchar](max) NULL,
	[OriginalSalesTaxGroup] [nvarchar](max) NULL,
	[IsLineDiscounted] [nvarchar](max) NULL,
	[ShelfNumber] [nvarchar](max) NULL,
	[ItemSalesTaxGroup] [nvarchar](max) NULL,
	[SerialNumber] [nvarchar](max) NULL,
	[OfferNumber] [nvarchar](max) NULL,
	[CostAmount] [float] NULL,
	[SectionNumber] [nvarchar](max) NULL,
	[IsWeightManuallyEntered] [nvarchar](max) NULL,
	[DiscountAmountForPrinting] [float] NULL,
	[CustomerInvoiceDiscountAmount] [float] NULL,
	[ProductScanned] [nvarchar](max) NULL,
	[PeriodicDiscountPercentage] [float] NULL,
	[ReturnTrackingStatus] [nvarchar](max) NULL,
	[ReturnLineNumber] [float] NULL,
	[PeriodicDiscountAmount] [float] NULL,
	[PeriodicDiscountGroup] [nvarchar](max) NULL,
	[PickupEndTime] [bigint] NULL
) ON [PRIMARY] TEXTIMAGE_ON [PRIMARY]
GO
/****** Object:  Table [dbo].[RETURN_Policy_data]    Script Date: 30/07/2025 12:27:44 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[RETURN_Policy_data](
	[Drug_id] [varchar](50) NULL,
	[DrugName] [varchar](254) NULL,
	[SubCategory] [varchar](1) NOT NULL,
	[Manf_id] [varchar](50) NULL,
	[Brand_Name] [varchar](50) NULL,
	[Cost] [varchar](50) NULL,
	[Agent_Name] [varchar](254) NULL,
	[Return_Type] [varchar](254) NULL,
	[BatchNo_New] [varchar](8000) NULL,
	[Batch_No] [varchar](50) NULL,
	[ExpDate] [datetime] NULL,
	[Stock] [float] NULL,
	[Warehouse] [varchar](50) NULL,
	[LocationID] [varchar](50) NULL,
	[Return_Policy] [varchar](254) NULL,
	[Return_Trigger_days] [varchar](50) NOT NULL,
	[Remarks] [varchar](56) NULL,
	[Loc_Grp] [varchar](6) NOT NULL
) ON [PRIMARY]
GO
/****** Object:  Table [dbo].[SalesOrderLines]    Script Date: 30/07/2025 12:27:44 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[SalesOrderLines](
	[RequestedReceiptDate] [nvarchar](max) NULL,
	[SalesOrderLineStatus] [nvarchar](max) NULL,
	[ItemNumber] [nvarchar](max) NULL,
	[ShippingWarehouseId] [nvarchar](max) NULL,
	[LineDiscountAmount] [float] NULL,
	[SalesUnitSymbol] [nvarchar](max) NULL,
	[OrderedSalesQuantity] [float] NULL,
	[LineAmount] [float] NULL
) ON [PRIMARY] TEXTIMAGE_ON [PRIMARY]
GO
/****** Object:  Table [dbo].[SalesOrderLines_yesterday]    Script Date: 30/07/2025 12:27:44 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[SalesOrderLines_yesterday](
	[RequestedReceiptDate] [nvarchar](max) NULL,
	[SalesOrderLineStatus] [nvarchar](max) NULL,
	[ItemNumber] [nvarchar](max) NULL,
	[ShippingWarehouseId] [nvarchar](max) NULL,
	[LineDiscountAmount] [float] NULL,
	[SalesUnitSymbol] [nvarchar](max) NULL,
	[OrderedSalesQuantity] [float] NULL,
	[LineAmount] [float] NULL
) ON [PRIMARY] TEXTIMAGE_ON [PRIMARY]
GO
/****** Object:  Table [dbo].[Stock_Batch_correction_final]    Script Date: 30/07/2025 12:27:44 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[Stock_Batch_correction_final](
	[Statement number] [varchar](50) NULL,
	[Store Code] [varchar](50) NULL,
	[Item number] [varchar](50) NULL,
	[Item Name] [varchar](254) NULL,
	[Site] [varchar](50) NULL,
	[Warehouse] [varchar](50) NULL,
	[Location] [varchar](50) NULL,
	[Old Batch number] [varchar](50) NULL,
	[New_Batch] [varchar](50) NULL,
	[New_Qty] [varchar](50) NULL,
	[Expiry Date] [varchar](50) NULL,
	[Unit] [varchar](50) NULL,
	[Sales qty] [varchar](50) NULL,
	[Old Available qty] [varchar](50) NULL,
	[New Available qty] [decimal](8, 2) NULL,
	[found batch] [int] NULL,
	[all Batch On Hand] [nvarchar](max) NULL,
	[Remarks] [varchar](31) NULL
) ON [PRIMARY] TEXTIMAGE_ON [PRIMARY]
GO
/****** Object:  Table [dbo].[Stock_by_Location_PIVOT_tbl]    Script Date: 30/07/2025 12:27:44 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[Stock_by_Location_PIVOT_tbl](
	[Item number] [nvarchar](max) NULL,
	[Product name] [nvarchar](max) NULL,
	[Drug_id] [varchar](50) NULL,
	[WH0001-STORE] [float] NULL,
	[WH0002-800STORE] [float] NULL,
	[AUH0001-800 CENT] [float] NULL,
	[AUH0002-800CAPTL] [float] NULL,
	[AUH0003-800ALAIN] [float] NULL,
	[DXB0001-GREENS] [float] NULL,
	[DXB0002-CARE] [float] NULL,
	[DXB0003-JUMEIRAH] [float] NULL,
	[DXB0004-ONECNTRL] [float] NULL,
	[DXB0005-GLDMILE1] [float] NULL,
	[DXB0006-GLDMILE2] [float] NULL,
	[DXB0007-ATLANTIS] [float] NULL,
	[DXB0008-ATLNTS 2] [float] NULL,
	[DXB0009-CENTER] [float] NULL,
	[DXB0010-KHAWANIJ] [float] NULL,
	[DXB0011-AVENUE] [float] NULL,
	[DXB0012-800 DHCC] [float] NULL,
	[DXB0013-800 PARK] [float] NULL,
	[DXB0014-800 PH] [float] NULL,
	[DXB0015-OLDTOWN] [float] NULL,
	[DXB0016-SOUTH1] [float] NULL,
	[DXB0017-PALM] [float] NULL,
	[DXB0018-CWALK1] [float] NULL,
	[DXB0019-800CRCLE] [float] NULL,
	[DXB0020-800ALQUZ] [float] NULL,
	[DXB0021-PROMINAD] [float] NULL,
	[DXB0022-CARE 5] [float] NULL,
	[DXB0023-800SARAY] [float] NULL,
	[DXB0024-ARJAN] [float] NULL,
	[DXB0025-800ARJAN] [float] NULL,
	[DXB0026-CARE 1] [float] NULL,
	[DXB0027-N.SHEBA] [float] NULL,
	[DXB0028-SHOROOQ] [float] NULL,
	[DXB0029-DCCS] [float] NULL,
	[DXB0030-CARE 2] [float] NULL,
	[DXB0031-CARE 3] [float] NULL,
	[DXB0032-BURJ] [float] NULL,
	[RAK0001-800RAK] [float] NULL,
	[SHJ0001-800 SHJ] [float] NULL,
	[SHJ0002-800ZAHIA] [float] NULL
) ON [PRIMARY] TEXTIMAGE_ON [PRIMARY]
GO
/****** Object:  Table [dbo].[Stock_by_Location_PIVOT1]    Script Date: 30/07/2025 12:27:44 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[Stock_by_Location_PIVOT1](
	[Item number] [varchar](50) NULL,
	[Product name] [varchar](254) NULL,
	[Drug_id] [varchar](50) NULL,
	[WH0001-STORE] [decimal](38, 2) NULL,
	[WH0002-800STORE] [decimal](38, 2) NULL,
	[AUH0001-800 CENT] [decimal](38, 2) NULL,
	[AUH0002-800CAPTL] [decimal](38, 2) NULL,
	[AUH0003-800ALAIN] [decimal](38, 2) NULL,
	[DXB0001-GREENS] [decimal](38, 2) NULL,
	[DXB0002-CARE] [decimal](38, 2) NULL,
	[DXB0003-JUMEIRAH] [decimal](38, 2) NULL,
	[DXB0004-ONECNTRL] [decimal](38, 2) NULL,
	[DXB0005-GLDMILE1] [decimal](38, 2) NULL,
	[DXB0006-GLDMILE2] [decimal](38, 2) NULL,
	[DXB0007-ATLANTIS] [decimal](38, 2) NULL,
	[DXB0008-ATLNTS 2] [decimal](38, 2) NULL,
	[DXB0009-CENTER] [decimal](38, 2) NULL,
	[DXB0010-KHAWANIJ] [decimal](38, 2) NULL,
	[DXB0011-AVENUE] [decimal](38, 2) NULL,
	[DXB0012-800 DHCC] [decimal](38, 2) NULL,
	[DXB0013-800 PARK] [decimal](38, 2) NULL,
	[DXB0014-800 PH] [decimal](38, 2) NULL,
	[DXB0015-OLDTOWN] [decimal](38, 2) NULL,
	[DXB0016-SOUTH1] [decimal](38, 2) NULL,
	[DXB0017-PALM] [decimal](38, 2) NULL,
	[DXB0018-CWALK1] [decimal](38, 2) NULL,
	[DXB0019-800CRCLE] [decimal](38, 2) NULL,
	[DXB0020-800ALQUZ] [decimal](38, 2) NULL,
	[DXB0021-PROMINAD] [decimal](38, 2) NULL,
	[DXB0022-CARE 5] [decimal](38, 2) NULL,
	[DXB0023-800SARAY] [decimal](38, 2) NULL,
	[DXB0024-ARJAN] [decimal](38, 2) NULL,
	[DXB0025-800ARJAN] [decimal](38, 2) NULL,
	[DXB0026-CARE 1] [decimal](38, 2) NULL,
	[DXB0027-N.SHEBA] [decimal](38, 2) NULL,
	[DXB0028-SHOROOQ] [decimal](38, 2) NULL,
	[DXB0029-DCCS] [decimal](38, 2) NULL,
	[DXB0030-CARE 2] [decimal](38, 2) NULL,
	[DXB0031-CARE 3] [decimal](38, 2) NULL,
	[DXB0032-BURJ] [decimal](38, 2) NULL,
	[RAK0001-800RAK] [decimal](38, 2) NULL,
	[SHJ0001-800 SHJ] [decimal](38, 2) NULL,
	[SHJ0002-800ZAHIA] [decimal](38, 2) NULL
) ON [PRIMARY]
GO
/****** Object:  Table [dbo].[Store_Code]    Script Date: 30/07/2025 12:27:44 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[Store_Code](
	[STORECODE] [varchar](50) NULL,
	[STORENAME] [varchar](50) NULL
) ON [PRIMARY]
GO
/****** Object:  Table [dbo].[TO_Headers]    Script Date: 30/07/2025 12:27:44 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[TO_Headers](
	[TransferOrderNumber] [nvarchar](max) NULL,
	[RequestedReceiptDate] [datetime2](0) NULL,
	[ShippingWarehouseId] [nvarchar](max) NULL,
	[ReceivingWarehouseId] [nvarchar](max) NULL,
	[ShippingAddressName] [nvarchar](max) NULL,
	[TransferOrderStatus] [nvarchar](max) NULL,
	[ReceivingAddressName] [nvarchar](max) NULL,
	[RequestedShippingDate] [datetime2](0) NULL,
	[Staff] [varchar](50) NULL,
	[pdf_file] [varchar](50) NULL
) ON [PRIMARY] TEXTIMAGE_ON [PRIMARY]
GO
/****** Object:  Table [dbo].[TO_OrderLines]    Script Date: 30/07/2025 12:27:44 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[TO_OrderLines](
	[TransferOrderNumber] [nvarchar](max) NULL,
	[LineNumber] [float] NULL,
	[TransferQuantity] [float] NULL,
	[LineStatus] [nvarchar](max) NULL,
	[ShippingSiteId] [nvarchar](max) NULL,
	[ItemNumber] [nvarchar](max) NULL,
	[ShippingWarehouseId] [nvarchar](max) NULL,
	[RequestedReceiptDate] [datetime2](0) NULL,
	[ShippedQuantity] [float] NULL,
	[ReceivedQuantity] [float] NULL,
	[ReceivingInventoryLotId] [nvarchar](max) NULL,
	[ShippingInventoryLotId] [nvarchar](max) NULL,
	[RemainingShippedQuantity] [float] NULL,
	[RequestedShippingDate] [datetime2](0) NULL,
	[ReceivingTransitInventoryLotId] [nvarchar](max) NULL,
	[ItemBatchNumber] [nvarchar](max) NULL
) ON [PRIMARY] TEXTIMAGE_ON [PRIMARY]
GO
/****** Object:  Table [dbo].[TOHeader]    Script Date: 30/07/2025 12:27:44 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[TOHeader](
	[TransferOrderNumber] [nvarchar](max) NULL,
	[TransferOrderStatus] [nvarchar](max) NULL,
	[ShippingWarehouseId] [nvarchar](max) NULL,
	[RequestedReceiptDate] [datetime2](0) NULL,
	[ShippingAddressName] [nvarchar](max) NULL,
	[RequestedShippingDate] [datetime2](0) NULL,
	[ReceivingAddressName] [nvarchar](max) NULL,
	[ReceivingWarehouseId] [nvarchar](max) NULL
) ON [PRIMARY] TEXTIMAGE_ON [PRIMARY]
GO
/****** Object:  Table [dbo].[TOHeader_1Month]    Script Date: 30/07/2025 12:27:44 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[TOHeader_1Month](
	[TransferOrderNumber] [nvarchar](max) NULL,
	[TransferOrderStatus] [nvarchar](max) NULL,
	[ShippingWarehouseId] [nvarchar](max) NULL,
	[RequestedReceiptDate] [datetime2](0) NULL,
	[ShippingAddressName] [nvarchar](max) NULL,
	[RequestedShippingDate] [datetime2](0) NULL,
	[ReceivingAddressName] [nvarchar](max) NULL,
	[ReceivingWarehouseId] [nvarchar](max) NULL
) ON [PRIMARY] TEXTIMAGE_ON [PRIMARY]
GO
/****** Object:  Table [dbo].[TOLines]    Script Date: 30/07/2025 12:27:44 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[TOLines](
	[TransferOrderNumber] [nvarchar](max) NULL,
	[LineNumber] [float] NULL,
	[TransferQuantity] [float] NULL,
	[ShippingSiteId] [nvarchar](max) NULL,
	[LineStatus] [nvarchar](max) NULL,
	[ItemNumber] [nvarchar](max) NULL,
	[ShippingWarehouseId] [nvarchar](max) NULL,
	[RequestedReceiptDate] [datetime2](0) NULL,
	[ReceivedQuantity] [float] NULL,
	[ShippedQuantity] [float] NULL,
	[ReceivingInventoryLotId] [nvarchar](max) NULL,
	[ShippingInventoryLotId] [nvarchar](max) NULL,
	[RemainingShippedQuantity] [float] NULL,
	[RequestedShippingDate] [datetime2](0) NULL,
	[ReceivingTransitInventoryLotId] [nvarchar](max) NULL,
	[ItemBatchNumber] [nvarchar](max) NULL
) ON [PRIMARY] TEXTIMAGE_ON [PRIMARY]
GO
/****** Object:  Table [dbo].[TOLines_1Month]    Script Date: 30/07/2025 12:27:44 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[TOLines_1Month](
	[TransferOrderNumber] [nvarchar](max) NULL,
	[LineNumber] [float] NULL,
	[TransferQuantity] [float] NULL,
	[ShippingSiteId] [nvarchar](max) NULL,
	[LineStatus] [nvarchar](max) NULL,
	[ItemNumber] [nvarchar](max) NULL,
	[ShippingWarehouseId] [nvarchar](max) NULL,
	[RequestedReceiptDate] [datetime2](0) NULL,
	[ReceivedQuantity] [float] NULL,
	[ShippedQuantity] [float] NULL,
	[ReceivingInventoryLotId] [nvarchar](max) NULL,
	[ShippingInventoryLotId] [nvarchar](max) NULL,
	[RemainingShippedQuantity] [float] NULL,
	[RequestedShippingDate] [datetime2](0) NULL,
	[ReceivingTransitInventoryLotId] [nvarchar](max) NULL,
	[ItemBatchNumber] [nvarchar](max) NULL
) ON [PRIMARY] TEXTIMAGE_ON [PRIMARY]
GO
/****** Object:  Table [dbo].[TransferOrderHeaders_Pending_WH]    Script Date: 30/07/2025 12:27:44 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[TransferOrderHeaders_Pending_WH](
	[TransferOrderNumber] [nvarchar](max) NULL,
	[RequestedReceiptDate] [datetime2](0) NULL,
	[ShippingWarehouseId] [nvarchar](max) NULL,
	[ReceivingWarehouseId] [nvarchar](max) NULL,
	[ShippingAddressName] [nvarchar](max) NULL,
	[TransferOrderStatus] [nvarchar](max) NULL,
	[ReceivingAddressName] [nvarchar](max) NULL,
	[RequestedShippingDate] [datetime2](0) NULL,
	[from_WH] [varchar](50) NULL,
	[to_WH] [varchar](50) NULL,
	[LocationID] [varchar](50) NULL
) ON [PRIMARY] TEXTIMAGE_ON [PRIMARY]
GO
/****** Object:  Table [dbo].[TransferOrderHeaders_Today]    Script Date: 30/07/2025 12:27:44 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[TransferOrderHeaders_Today](
	[TransferOrderNumber] [nvarchar](max) NULL,
	[RequestedReceiptDate] [datetime2](0) NULL,
	[ShippingWarehouseId] [nvarchar](max) NULL,
	[ReceivingWarehouseId] [nvarchar](max) NULL,
	[ShippingAddressName] [nvarchar](max) NULL,
	[TransferOrderStatus] [nvarchar](max) NULL,
	[ReceivingAddressName] [nvarchar](max) NULL,
	[RequestedShippingDate] [datetime2](0) NULL
) ON [PRIMARY] TEXTIMAGE_ON [PRIMARY]
GO
/****** Object:  Table [dbo].[TransferOrderHeaders_transit]    Script Date: 30/07/2025 12:27:44 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[TransferOrderHeaders_transit](
	[TransferOrderNumber] [nvarchar](max) NULL,
	[RequestedReceiptDate] [datetime2](0) NULL,
	[ShippingWarehouseId] [nvarchar](max) NULL,
	[ReceivingWarehouseId] [nvarchar](max) NULL,
	[ShippingAddressName] [nvarchar](max) NULL,
	[TransferOrderStatus] [nvarchar](max) NULL,
	[ReceivingAddressName] [nvarchar](max) NULL,
	[RequestedShippingDate] [datetime2](0) NULL
) ON [PRIMARY] TEXTIMAGE_ON [PRIMARY]
GO
/****** Object:  Table [dbo].[TransferOrderLines_Pending_InBR2WH_Transit]    Script Date: 30/07/2025 12:27:44 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[TransferOrderLines_Pending_InBR2WH_Transit](
	[TransferOrderNumber] [nvarchar](max) NULL,
	[LineNumber] [float] NULL,
	[TransferQuantity] [float] NULL,
	[LineStatus] [nvarchar](max) NULL,
	[ShippingSiteId] [nvarchar](max) NULL,
	[ItemNumber] [nvarchar](max) NULL,
	[ShippingWarehouseId] [nvarchar](max) NULL,
	[RequestedReceiptDate] [datetime2](0) NULL,
	[ShippedQuantity] [float] NULL,
	[ReceivedQuantity] [float] NULL,
	[ReceivingInventoryLotId] [nvarchar](max) NULL,
	[ShippingInventoryLotId] [nvarchar](max) NULL,
	[RemainingShippedQuantity] [float] NULL,
	[RequestedShippingDate] [datetime2](0) NULL,
	[ReceivingTransitInventoryLotId] [nvarchar](max) NULL,
	[ItemBatchNumber] [nvarchar](max) NULL,
	[TransferOrderStatus] [nvarchar](max) NULL,
	[ReceivingWarehouseId] [nvarchar](max) NULL
) ON [PRIMARY] TEXTIMAGE_ON [PRIMARY]
GO
/****** Object:  Table [dbo].[TransferOrderLines_Pending_WH]    Script Date: 30/07/2025 12:27:44 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[TransferOrderLines_Pending_WH](
	[TransferOrderNumber] [nvarchar](max) NULL,
	[LineNumber] [float] NULL,
	[TransferQuantity] [float] NULL,
	[LineStatus] [nvarchar](max) NULL,
	[ShippingSiteId] [nvarchar](max) NULL,
	[ItemNumber] [nvarchar](max) NULL,
	[ShippingWarehouseId] [nvarchar](max) NULL,
	[RequestedReceiptDate] [datetime2](0) NULL,
	[ShippedQuantity] [float] NULL,
	[ReceivedQuantity] [float] NULL,
	[ReceivingInventoryLotId] [nvarchar](max) NULL,
	[ShippingInventoryLotId] [nvarchar](max) NULL,
	[RemainingShippedQuantity] [float] NULL,
	[RequestedShippingDate] [datetime2](0) NULL,
	[ReceivingTransitInventoryLotId] [nvarchar](max) NULL,
	[ItemBatchNumber] [nvarchar](max) NULL,
	[TransferOrderStatus] [nvarchar](max) NULL,
	[Expr1] [nvarchar](max) NULL,
	[ProductName] [nvarchar](max) NULL,
	[ProductGroupId] [nvarchar](max) NULL
) ON [PRIMARY] TEXTIMAGE_ON [PRIMARY]
GO
/****** Object:  Table [dbo].[TransferOrderLines_SKU_QTY]    Script Date: 30/07/2025 12:27:44 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[TransferOrderLines_SKU_QTY](
	[TransferOrderNumber] [nvarchar](max) NULL,
	[SKU] [int] NULL,
	[QTY] [float] NULL
) ON [PRIMARY] TEXTIMAGE_ON [PRIMARY]
GO
/****** Object:  Table [dbo].[TransferOrderLines_Today]    Script Date: 30/07/2025 12:27:44 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[TransferOrderLines_Today](
	[TransferOrderNumber] [nvarchar](max) NULL,
	[LineNumber] [float] NULL,
	[TransferQuantity] [float] NULL,
	[LineStatus] [nvarchar](max) NULL,
	[ShippingSiteId] [nvarchar](max) NULL,
	[ItemNumber] [nvarchar](max) NULL,
	[ShippingWarehouseId] [nvarchar](max) NULL,
	[RequestedReceiptDate] [datetime2](0) NULL,
	[ShippedQuantity] [float] NULL,
	[ReceivedQuantity] [float] NULL,
	[ReceivingInventoryLotId] [nvarchar](max) NULL,
	[ShippingInventoryLotId] [nvarchar](max) NULL,
	[RemainingShippedQuantity] [float] NULL,
	[RequestedShippingDate] [datetime2](0) NULL,
	[ReceivingTransitInventoryLotId] [nvarchar](max) NULL,
	[ItemBatchNumber] [nvarchar](max) NULL
) ON [PRIMARY] TEXTIMAGE_ON [PRIMARY]
GO
/****** Object:  Table [dbo].[TransferOrderLines_transit]    Script Date: 30/07/2025 12:27:44 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[TransferOrderLines_transit](
	[TransferOrderNumber] [nvarchar](max) NULL,
	[LineNumber] [float] NULL,
	[TransferQuantity] [float] NULL,
	[LineStatus] [nvarchar](max) NULL,
	[ShippingSiteId] [nvarchar](max) NULL,
	[ItemNumber] [nvarchar](max) NULL,
	[ShippingWarehouseId] [nvarchar](max) NULL,
	[RequestedReceiptDate] [datetime2](0) NULL,
	[ShippedQuantity] [float] NULL,
	[ReceivedQuantity] [float] NULL,
	[ReceivingInventoryLotId] [nvarchar](max) NULL,
	[ShippingInventoryLotId] [nvarchar](max) NULL,
	[RemainingShippedQuantity] [float] NULL,
	[RequestedShippingDate] [datetime2](0) NULL,
	[ReceivingTransitInventoryLotId] [nvarchar](max) NULL,
	[ItemBatchNumber] [nvarchar](max) NULL
) ON [PRIMARY] TEXTIMAGE_ON [PRIMARY]
GO
/****** Object:  Table [dbo].[TransferOrderLines_Upload_Raw2]    Script Date: 30/07/2025 12:27:44 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[TransferOrderLines_Upload_Raw2](
	[Item number] [varchar](50) NULL,
	[Physical date] [varchar](50) NULL,
	[Financial date] [varchar](50) NULL,
	[Reference] [varchar](50) NULL,
	[Number] [varchar](50) NULL,
	[Receipt] [varchar](50) NULL,
	[Issue] [varchar](50) NULL,
	[Quantity] [varchar](50) NULL,
	[Unit] [varchar](50) NULL,
	[CW quantity] [varchar](50) NULL,
	[CW unit] [varchar](50) NULL,
	[Cost amount] [varchar](50) NULL,
	[Batch number] [varchar](50) NULL,
	[Batch number2] [varchar](50) NULL
) ON [PRIMARY]
GO
/****** Object:  Table [dbo].[VendorInvoiceHeaders]    Script Date: 30/07/2025 12:27:44 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[VendorInvoiceHeaders](
	[dataAreaId] [nvarchar](max) NULL,
	[HeaderReference] [nvarchar](max) NULL,
	[FiscalEstablishmentId] [nvarchar](max) NULL,
	[FiscalDocumentOperationTypeId] [nvarchar](max) NULL,
	[PaymentId] [nvarchar](max) NULL,
	[EndDateTime] [datetime2](0) NULL,
	[CarrierName] [nvarchar](max) NULL,
	[Site] [nvarchar](max) NULL,
	[IsApproved] [nvarchar](max) NULL,
	[ErrorInvalidDistribution] [nvarchar](max) NULL,
	[VendorName] [nvarchar](max) NULL,
	[UUID] [nvarchar](max) NULL,
	[FiscalDocumentSpecie] [nvarchar](max) NULL,
	[NumberSequenceGroup] [nvarchar](max) NULL,
	[DeliveryFreightChargeTerms] [nvarchar](max) NULL,
	[InvoiceAccount] [nvarchar](max) NULL,
	[ReleaseDateComment] [nvarchar](max) NULL,
	[InvoiceReceivedDate] [datetime2](0) NULL,
	[PostingProfile] [nvarchar](max) NULL,
	[IsOnHold] [nvarchar](max) NULL,
	[BankAccount] [nvarchar](max) NULL,
	[Recalculation] [bit] NULL,
	[CFPSCode] [nvarchar](max) NULL,
	[VarianceApprovedDateTime] [datetime2](0) NULL,
	[VendorInvoiceReviewStatus] [nvarchar](max) NULL,
	[Warehouse] [nvarchar](max) NULL,
	[VendorPaymentFineCode] [nvarchar](max) NULL,
	[InvoiceDescription] [nvarchar](max) NULL,
	[DiscountPercentage] [float] NULL,
	[TermsOfPayment] [nvarchar](max) NULL,
	[DeliveryPackingName] [nvarchar](max) NULL,
	[TotalDiscount] [float] NULL,
	[BankSpecificSymbol] [nvarchar](max) NULL,
	[MethodOfPayment] [nvarchar](max) NULL,
	[BankConstantSymbol] [nvarchar](max) NULL,
	[PaymentSchedule] [nvarchar](max) NULL,
	[GSTInvoiceType] [nvarchar](max) NULL,
	[ExchangeRate] [float] NULL,
	[Port] [nvarchar](max) NULL,
	[TransactionCode] [nvarchar](max) NULL,
	[ListCode] [nvarchar](max) NULL,
	[DimensionDisplayValue] [nvarchar](max) NULL,
	[CreditCorrection] [nvarchar](max) NULL,
	[FiscalOperationPresenceType] [nvarchar](max) NULL,
	[VendorPaymentFinancialInterestCode] [nvarchar](max) NULL,
	[DocumentNumber] [nvarchar](max) NULL,
	[Date] [datetime2](0) NULL,
	[PurchaseOrderNumber] [nvarchar](max) NULL,
	[ReportingCurrencyExchangeRate] [float] NULL,
	[Transport] [nvarchar](max) NULL,
	[VariancePersonnelNumber] [nvarchar](max) NULL,
	[PaymentGroupCode] [nvarchar](max) NULL,
	[CTeType] [nvarchar](max) NULL,
	[ChargesGroup] [nvarchar](max) NULL,
	[CashDiscount] [float] NULL,
	[TaxExemptNumber] [nvarchar](max) NULL,
	[StartDateTime] [datetime2](0) NULL,
	[Currency] [nvarchar](max) NULL,
	[InvoiceDate] [datetime2](0) NULL,
	[BusinessDocumentSubmissionId_W] [nvarchar](max) NULL,
	[ServiceCodeOnDeliveryAddress] [nvarchar](max) NULL,
	[InvoicePaymentReleaseDate] [datetime2](0) NULL,
	[CountyOrigDest] [nvarchar](max) NULL,
	[CashDiscountCode] [nvarchar](max) NULL,
	[CashDiscountDate] [datetime2](0) NULL,
	[ImportedSalesTax] [float] NULL,
	[DeliveryVehicleNumber] [nvarchar](max) NULL,
	[Log] [nvarchar](max) NULL,
	[GSTImportDeclarationNumber] [nvarchar](max) NULL,
	[ImportedAmount] [float] NULL,
	[Triangulation] [nvarchar](max) NULL,
	[SecondaryExchangeRate] [float] NULL,
	[DueDate] [datetime2](0) NULL,
	[OverrideSalesTax] [nvarchar](max) NULL,
	[IgnoreCalculatedSalesTax] [nvarchar](max) NULL,
	[VendorRequestedWorkerEmail] [nvarchar](max) NULL,
	[SalesTaxRounding] [float] NULL,
	[InvoiceNumber] [nvarchar](max) NULL,
	[InvoiceRoundOff] [float] NULL,
	[IsBatch] [nvarchar](max) NULL,
	[FiscalDocumentTypeId] [nvarchar](max) NULL,
	[DeliveryStateRegistered] [nvarchar](max) NULL,
	[DeliveryName] [nvarchar](max) NULL,
	[IsFinalUser] [nvarchar](max) NULL,
	[ApprovePostingWithMatchingDiscrepancies] [nvarchar](max) NULL,
	[Comment] [nvarchar](max) NULL,
	[HeaderOnlyImport] [nvarchar](max) NULL,
	[EnterpriseNumber] [nvarchar](max) NULL,
	[ImportDeclarationNumber] [nvarchar](max) NULL,
	[VendorAccount] [nvarchar](max) NULL,
	[VendorInvoiceType] [nvarchar](max) NULL,
	[FiscalDocumentModel] [nvarchar](max) NULL,
	[IsElectronicInvoiceForService] [nvarchar](max) NULL,
	[SalesTaxGroup] [nvarchar](max) NULL,
	[FiscalDocumentSeries] [nvarchar](max) NULL,
	[InvoiceGroup] [nvarchar](max) NULL,
	[IsPricesIncludeSalesTax] [nvarchar](max) NULL,
	[InvoiceSeries] [nvarchar](max) NULL,
	[StatisticsProcedure] [nvarchar](max) NULL,
	[FixedRate] [nvarchar](max) NULL,
	[DeliveryTransportBrand] [nvarchar](max) NULL,
	[ApproverPersonnelNumber] [nvarchar](max) NULL,
	[PurchIdRange] [nvarchar](max) NULL,
	[PaymentSpecification] [nvarchar](max) NULL,
	[PackingslipRange] [nvarchar](max) NULL,
	[SettleVoucher] [nvarchar](max) NULL,
	[PurchReceiptDate_W] [datetime2](0) NULL,
	[FreightedBy] [nvarchar](max) NULL,
	[AccessKey] [nvarchar](max) NULL,
	[ProjectManager_FR] [nvarchar](max) NULL,
	[InvoiceAccountServiceCode_FR] [nvarchar](max) NULL,
	[ElectronicInvoiceFrameworkType_FR] [bigint] NULL,
	[ProjectManagerServiceCode_FR] [nvarchar](max) NULL,
	[PSNPostingDefinitionCode] [nvarchar](max) NULL,
	[PSNVendorAccountForBalancePayoff] [nvarchar](max) NULL,
	[PSNReferenceInvoiceNumber] [nvarchar](max) NULL,
	[PSNBankAccountId] [nvarchar](max) NULL,
	[PSNPurchasingCardTransactionType] [nvarchar](max) NULL,
	[PSNCardNumberDigits] [nvarchar](max) NULL,
	[PSNCardHolderName] [nvarchar](max) NULL,
	[DTEFileName] [nvarchar](max) NULL,
	[DTEDigest] [nvarchar](max) NULL,
	[DocumentClassificationId] [nvarchar](max) NULL,
	[DTEShipmentID] [nvarchar](max) NULL,
	[WithholdingSetID] [nvarchar](max) NULL,
	[DocumentClassificationNumber] [nvarchar](max) NULL
) ON [PRIMARY] TEXTIMAGE_ON [PRIMARY]
GO
/****** Object:  Table [dbo].[VendorInvoiceLines]    Script Date: 30/07/2025 12:27:44 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[VendorInvoiceLines](
	[dataAreaId] [nvarchar](max) NULL,
	[HeaderReference] [nvarchar](max) NULL,
	[InvoiceLineNumber] [float] NULL,
	[Tax1099SClosingDate] [datetime2](0) NULL,
	[ChargesOnPurchases] [float] NULL,
	[Commodity] [nvarchar](max) NULL,
	[PriceUnit] [float] NULL,
	[OrderedInventoryStatusId] [nvarchar](max) NULL,
	[Tax1099GVendorStateTaxId] [nvarchar](max) NULL,
	[ProductStyleId] [nvarchar](max) NULL,
	[Tax1099Amount] [float] NULL,
	[DimensionDisplayValue] [nvarchar](max) NULL,
	[WithholdingTaxGroup] [nvarchar](max) NULL,
	[Percentage] [float] NULL,
	[RemainAfterInvent] [float] NULL,
	[RetainPercentage] [float] NULL,
	[TaxWithholdGroup] [nvarchar](max) NULL,
	[TotalRetainedAmount] [float] NULL,
	[LineNumber] [float] NULL,
	[VendorAccount] [nvarchar](max) NULL,
	[UnitPrice] [float] NULL,
	[LineDescription] [nvarchar](max) NULL,
	[ItemNumber] [nvarchar](max) NULL,
	[Tax1099GVendorStateId] [nvarchar](max) NULL,
	[ItemName] [nvarchar](max) NULL,
	[ProcurementCategoryHierarchyName] [nvarchar](max) NULL,
	[Tax1099SAddressOrLegalDescription] [nvarchar](max) NULL,
	[Tax1099GTaxYear] [bigint] NULL,
	[DeliveryState] [nvarchar](max) NULL,
	[RemainBeforeInvent] [float] NULL,
	[CWDeliveryRemainder] [float] NULL,
	[TaxServiceCode] [nvarchar](max) NULL,
	[ProductSizeId] [nvarchar](max) NULL,
	[InventoryWarehouseId] [nvarchar](max) NULL,
	[PartyID] [nvarchar](max) NULL,
	[MultilineDiscount] [float] NULL,
	[Tax1099GStateTaxWithheldAmount] [float] NULL,
	[AdjustedUnitPrice] [float] NULL,
	[CWRemainingQuantity] [float] NULL,
	[Ordering] [nvarchar](max) NULL,
	[AccountingDistributionTemplateId] [nvarchar](max) NULL,
	[RemainAfter] [float] NULL,
	[CWUpdate] [float] NULL,
	[Transport] [nvarchar](max) NULL,
	[RemainBefore] [float] NULL,
	[IsTax1099GTradeOrBusinessIncome] [nvarchar](max) NULL,
	[ReleaseAllRetainedAmount] [nvarchar](max) NULL,
	[Unit] [nvarchar](max) NULL,
	[Discount] [float] NULL,
	[Tax1099SBuyerPartOfRealEstateTaxAmount] [float] NULL,
	[Tax1099StateAmount] [float] NULL,
	[NetAmount] [float] NULL,
	[PurchaseOrder] [nvarchar](max) NULL,
	[LineType] [nvarchar](max) NULL,
	[DataAreaCompany] [nvarchar](max) NULL,
	[MultilineDiscountPercentage] [float] NULL,
	[CFOPCode] [nvarchar](max) NULL,
	[VendorInvoiceLineReviewStatus] [nvarchar](max) NULL,
	[ItemSalesTax] [nvarchar](max) NULL,
	[ProductConfigurationId] [nvarchar](max) NULL,
	[CountyOrigDest] [nvarchar](max) NULL,
	[BudgetReservationDocumentNumber] [nvarchar](max) NULL,
	[SalesTaxGroup] [nvarchar](max) NULL,
	[BudgetReservationLineNumber] [bigint] NULL,
	[TransactionCode] [nvarchar](max) NULL,
	[PDSCalculationId] [nvarchar](max) NULL,
	[InventorySiteId] [nvarchar](max) NULL,
	[IsTax1099SPropertyOrServices] [nvarchar](max) NULL,
	[StatisticsProcedure] [nvarchar](max) NULL,
	[ProductVersionId] [nvarchar](max) NULL,
	[RetainageAmount] [float] NULL,
	[DiotOperationType] [nvarchar](max) NULL,
	[Amount] [float] NULL,
	[DeliveryName] [nvarchar](max) NULL,
	[MainAccountDisplayValue] [nvarchar](max) NULL,
	[Tax1099Type] [nvarchar](max) NULL,
	[DimensionNumber] [nvarchar](max) NULL,
	[TaxWithholdItemGroupName] [nvarchar](max) NULL,
	[InventNow] [float] NULL,
	[ItemBatchNumber] [nvarchar](max) NULL,
	[ProductColorId] [nvarchar](max) NULL,
	[ReceiveNow] [float] NULL,
	[OverrideSalesTax] [nvarchar](max) NULL,
	[OrigCountryRegionId] [nvarchar](max) NULL,
	[Port] [nvarchar](max) NULL,
	[Tax1099Box] [nvarchar](max) NULL,
	[InvoiceAccount] [nvarchar](max) NULL,
	[ProcurementCategoryName] [nvarchar](max) NULL,
	[WithholdingTaxItemGroup] [nvarchar](max) NULL,
	[Currency] [nvarchar](max) NULL,
	[OriginalDeliverRemainder] [float] NULL,
	[PurchLineNumber] [bigint] NULL,
	[CloseForReceipt] [nvarchar](max) NULL,
	[DiscountPercent] [float] NULL,
	[ChangeQuantityManually] [nvarchar](max) NULL,
	[StateOfOrigin] [nvarchar](max) NULL
) ON [PRIMARY] TEXTIMAGE_ON [PRIMARY]
GO
/****** Object:  Table [dbo].[VendorPaymentJournalHeaders]    Script Date: 30/07/2025 12:27:44 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[VendorPaymentJournalHeaders](
	[dataAreaId] [nvarchar](max) NULL,
	[JournalBatchNumber] [nvarchar](max) NULL,
	[JournalName] [nvarchar](max) NULL,
	[ChargeBearer] [bigint] NULL,
	[OverrideSalesTax] [nvarchar](max) NULL,
	[Description] [nvarchar](max) NULL,
	[CategoryPurpose] [bigint] NULL,
	[IsPosted] [nvarchar](max) NULL,
	[LocalInstrument] [bigint] NULL,
	[ServiceLevel] [bigint] NULL
) ON [PRIMARY] TEXTIMAGE_ON [PRIMARY]
GO
/****** Object:  Table [dbo].[VendorPaymentJournalLineSettledInvoices]    Script Date: 30/07/2025 12:27:44 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[VendorPaymentJournalLineSettledInvoices](
	[JournalLineCompany] [nvarchar](max) NULL,
	[JournalBatchNumber] [nvarchar](max) NULL,
	[JournalLineNumber] [float] NULL,
	[InvoiceNumber] [nvarchar](max) NULL,
	[InvoiceCompany] [nvarchar](max) NULL,
	[InvoiceDueDate] [datetime2](0) NULL,
	[InvoiceToPaymentCrossRate] [float] NULL,
	[SettlementAmountInInvoiceCurrency] [float] NULL,
	[CashDiscountToTakeInInvoiceCurrency] [float] NULL,
	[invoiceAccount] [nvarchar](max) NULL,
	[AccountDisplayValue] [nvarchar](max) NULL
) ON [PRIMARY] TEXTIMAGE_ON [PRIMARY]
GO
/****** Object:  Table [dbo].[VendTransBiEntities]    Script Date: 30/07/2025 12:27:44 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[VendTransBiEntities](
	[dataAreaId] [nvarchar](max) NULL,
	[SourceKey] [bigint] NULL,
	[SettleTax1099StateAmount] [float] NULL,
	[PaymTermId] [nvarchar](max) NULL,
	[LastSettleVoucher] [nvarchar](max) NULL,
	[Voucher] [nvarchar](max) NULL,
	[SysModifiedDateTime] [datetime2](0) NULL,
	[Tax1099Amount] [float] NULL,
	[LastSettleDate] [datetime2](0) NULL,
	[Txt] [nvarchar](max) NULL,
	[ReasonRefRecId] [bigint] NULL,
	[LastExchAdjRate] [float] NULL,
	[ReportingCurrencyCrossRate] [float] NULL,
	[CashDiscBaseDate] [datetime2](0) NULL,
	[SettleTax1099Amount] [float] NULL,
	[PaymSpec] [nvarchar](max) NULL,
	[Settlement] [nvarchar](max) NULL,
	[LastSettleCompany] [nvarchar](max) NULL,
	[LastSettleAccountNum] [nvarchar](max) NULL,
	[PostingProfileApprove] [nvarchar](max) NULL,
	[EUROTriangulation] [nvarchar](max) NULL,
	[BankCentralBankPurposeText] [nvarchar](max) NULL,
	[AccountingEvent] [bigint] NULL,
	[TransDate] [datetime2](0) NULL,
	[PaymMode] [nvarchar](max) NULL,
	[RemittanceLocation] [bigint] NULL,
	[SettleAmountCur] [float] NULL,
	[SysModifiedTransactionId] [bigint] NULL,
	[BankRemittanceFileId] [nvarchar](max) NULL,
	[Prepayment] [nvarchar](max) NULL,
	[ExchRate] [float] NULL,
	[AmountMST] [float] NULL,
	[ReportingCurrencyAmount] [float] NULL,
	[PostingProfileClose] [nvarchar](max) NULL,
	[PromissoryNoteSeqNum] [bigint] NULL,
	[JournalNum] [nvarchar](max) NULL,
	[Closed] [datetime2](0) NULL,
	[ThirdPartyBankAccountId] [nvarchar](max) NULL,
	[AmountCur] [float] NULL,
	[VendExchAdjustmentUnrealized] [float] NULL,
	[DocumentDate] [datetime2](0) NULL,
	[PaymId] [nvarchar](max) NULL,
	[SysCreatedBy] [nvarchar](max) NULL,
	[PromissoryNoteID] [nvarchar](max) NULL,
	[Tax1099RecId] [bigint] NULL,
	[SettleAmountReporting] [float] NULL,
	[SettleAmountMST] [float] NULL,
	[ReportingExchAdjustmentRealized] [float] NULL,
	[DocumentNum] [nvarchar](max) NULL,
	[Tax1099Date] [datetime2](0) NULL,
	[VendPaymentGroup] [nvarchar](max) NULL,
	[ExchAdjustment] [float] NULL,
	[Tax1099StateAmount] [float] NULL,
	[PromissoryNoteStatus] [nvarchar](max) NULL,
	[SysCreatedTransactionId] [bigint] NULL,
	[ReleaseDateComment] [nvarchar](max) NULL,
	[ExchAdjustmentReporting] [float] NULL,
	[LastExchAdjRateReporting] [float] NULL,
	[OffsetRecid] [bigint] NULL,
	[Approver] [bigint] NULL,
	[LastExchAdjVoucher] [nvarchar](max) NULL,
	[RemittanceAddress] [bigint] NULL,
	[ArrivalAccountId] [nvarchar](max) NULL,
	[BankLCImportLine] [bigint] NULL,
	[Invoice] [nvarchar](max) NULL,
	[CompanyBankAccountId] [nvarchar](max) NULL,
	[Tax1099Fields] [bigint] NULL,
	[DueDate] [datetime2](0) NULL,
	[ReportingCurrencyExchRate] [float] NULL,
	[Arrival] [nvarchar](max) NULL,
	[Cancel] [nvarchar](max) NULL,
	[AccountNum] [nvarchar](max) NULL,
	[SysDataAreaId] [nvarchar](max) NULL,
	[TransType] [nvarchar](max) NULL,
	[PostingProfileCancel] [nvarchar](max) NULL,
	[SysRecVersion] [bigint] NULL,
	[InvoiceReleaseDate] [datetime2](0) NULL,
	[PostingProfile] [nvarchar](max) NULL,
	[BankCentralBankPurposeCode] [nvarchar](max) NULL,
	[ExchRateSecond] [float] NULL,
	[Correct] [nvarchar](max) NULL,
	[TaxInvoicePurchId] [nvarchar](max) NULL,
	[CashDiscCode] [nvarchar](max) NULL,
	[ReportingExchAdjustmentUnrealized] [float] NULL,
	[VendExchAdjustmentRealized] [float] NULL,
	[InvoiceProject] [nvarchar](max) NULL,
	[VendorVATDate] [datetime2](0) NULL,
	[LastExchAdj] [datetime2](0) NULL,
	[CreatedOn] [datetime2](0) NULL,
	[SummaryAccountId] [nvarchar](max) NULL,
	[CurrencyCode] [nvarchar](max) NULL,
	[ReportingCurrencyExchRateSecondary] [float] NULL,
	[FixedExchRate] [nvarchar](max) NULL,
	[ApprovedDate] [datetime2](0) NULL,
	[Approved] [nvarchar](max) NULL,
	[PostingProfileReOpen] [nvarchar](max) NULL,
	[RBOVendTrans] [nvarchar](max) NULL,
	[SysModifiedBy] [nvarchar](max) NULL,
	[PaymReference] [nvarchar](max) NULL,
	[Tax1099State] [nvarchar](max) NULL,
	[Tax1099Num] [nvarchar](max) NULL
) ON [PRIMARY] TEXTIMAGE_ON [PRIMARY]
GO
/****** Object:  Table [dbo].[Warehouses]    Script Date: 30/07/2025 12:27:44 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE TABLE [dbo].[Warehouses](
	[dataAreaId] [nvarchar](max) NULL,
	[WarehouseId] [nvarchar](max) NULL,
	[AreLaborStandardsAllowed] [nvarchar](max) NULL,
	[AreAdvancedWarehouseManagementProcessesEnabled] [nvarchar](max) NULL,
	[PrimaryAddressLatitude] [float] NULL,
	[WarehouseSpecificDefaultInventoryStatusId] [nvarchar](max) NULL,
	[ArePickingListsShipmentSpecificOnly] [nvarchar](max) NULL,
	[RawMaterialPickingInventoryIssueStatus] [nvarchar](max) NULL,
	[QuarantineWarehouseId] [nvarchar](max) NULL,
	[LoadReleaseReservationPolicyRule] [nvarchar](max) NULL,
	[InventoryCountingReasonCodePolicyName] [nvarchar](max) NULL,
	[WillWarehouseLocationIdIncludeShelfIdByDefault] [nvarchar](max) NULL,
	[ArePickingListsDeliveryModeSpecific] [nvarchar](max) NULL,
	[FormattedPrimaryAddress] [nvarchar](max) NULL,
	[WillManualLoadReleaseReserveInventory] [nvarchar](max) NULL,
	[WarehouseLocationIdBinIdFormat] [nvarchar](max) NULL,
	[AreItemsCoveragePlannedManually] [nvarchar](max) NULL,
	[WillShippingCancellationDecrementLoadQuanity] [nvarchar](max) NULL,
	[AutoUpdateShipmentRule] [nvarchar](max) NULL,
	[PrimaryAddressStateId] [nvarchar](max) NULL,
	[PrimaryAddressBuildingCompliment] [nvarchar](max) NULL,
	[WarehouseLocationIdRackIdFormat] [nvarchar](max) NULL,
	[PrimaryAddressLocationSalesTaxGroupCode] [nvarchar](max) NULL,
	[IsRefilledFromMainWarehouse] [nvarchar](max) NULL,
	[PrimaryAddressCountryRegionId] [nvarchar](max) NULL,
	[WillWarehouseLocationIdIncludeRackIdByDefault] [nvarchar](max) NULL,
	[RetailStoreQuantityAllocationReplenismentRuleWeight] [float] NULL,
	[IsPalletMovementDuringCycleCountingAllowed] [nvarchar](max) NULL,
	[WarehouseLocationIdShelfIdFormat] [nvarchar](max) NULL,
	[PrimaryAddressCountyId] [nvarchar](max) NULL,
	[WarehouseWorkProcessingPolicyName] [nvarchar](max) NULL,
	[MasterPlanningWorkCalendardId] [nvarchar](max) NULL,
	[ExternallyLocatedWarehouseVendorAccountNumber] [nvarchar](max) NULL,
	[MainRefillingWarehouseId] [nvarchar](max) NULL,
	[WillAutomaticLoadReleaseReserveInventory] [nvarchar](max) NULL,
	[IsPhysicalNegativeRetailStoreInventoryAllowed] [nvarchar](max) NULL,
	[PrimaryAddressLocationRoles] [nvarchar](max) NULL,
	[ExternallyLocatedWarehouseCustomerAccountNumber] [nvarchar](max) NULL,
	[PrimaryAddressDistrictName] [nvarchar](max) NULL,
	[IsRetailStoreWarehouse] [nvarchar](max) NULL,
	[IsBillOfLadingPrintingBeforeShipmentConfirmationEnabled] [nvarchar](max) NULL,
	[WarehouseName] [nvarchar](max) NULL,
	[WillInventoryStatusChangeRemoveBlocking] [nvarchar](max) NULL,
	[PrimaryAddressStreet] [nvarchar](max) NULL,
	[DefaultContainerTypeId] [nvarchar](max) NULL,
	[LanguageUsedForDomesticHazardousMaterialsShippingDocuments] [nvarchar](max) NULL,
	[IdentificationGroup] [nvarchar](max) NULL,
	[PrimaryAddressDescription] [nvarchar](max) NULL,
	[WillProductionBOMsReserveWarehouseLevelOnly] [nvarchar](max) NULL,
	[PrimaryAddressCity] [nvarchar](max) NULL,
	[PrimaryAddressStreetInKana] [nvarchar](max) NULL,
	[PrimaryAddressStreetNumber] [nvarchar](max) NULL,
	[PrimaryAddressZipCode] [nvarchar](max) NULL,
	[WillWarehouseLocationIdIncludeBinIdByDefault] [nvarchar](max) NULL,
	[MaximumBatchPickingListQuantity] [bigint] NULL,
	[AreWarehouseLocationCheckDigitsUnique] [nvarchar](max) NULL,
	[IsPrimaryAddressAssigned] [nvarchar](max) NULL,
	[ShouldWarehouseLocationIdIncludeAisleId] [nvarchar](max) NULL,
	[InventoryStatusChangeReservationRemovalLevel] [nvarchar](max) NULL,
	[LanguageUsedForExportHazardousMaterialsShippingDocuments] [nvarchar](max) NULL,
	[WarehouseReleaseReservationRequirementRuleFailureOption] [nvarchar](max) NULL,
	[PrimaryAddressTimeZone] [nvarchar](max) NULL,
	[TransitWarehouseId] [nvarchar](max) NULL,
	[PrimaryAddressCityInKana] [nvarchar](max) NULL,
	[WarehouseType] [nvarchar](max) NULL,
	[IsFinancialNegativeRetailStoreInventoryAllowed] [nvarchar](max) NULL,
	[MaximumPickingListLineQuantity] [bigint] NULL,
	[WarehouseReleaseReservationRequirementRule] [nvarchar](max) NULL,
	[WillOrderReleasingConsolidateShipments] [nvarchar](max) NULL,
	[PrimaryAddressPostBox] [nvarchar](max) NULL,
	[PrimaryAddressLongitude] [float] NULL,
	[OperationalSiteId] [nvarchar](max) NULL,
	[IsFallbackWarehouse] [nvarchar](max) NULL,
	[InventProfileType_RU] [nvarchar](max) NULL,
	[InventProfileId_RU] [nvarchar](max) NULL,
	[ActivityType_RU] [nvarchar](max) NULL,
	[InventLocationIdGoodsInRoute_RU] [nvarchar](max) NULL,
	[RBODefaultInventProfileId_RU] [nvarchar](max) NULL,
	[NumberSequenceGroup_RU] [nvarchar](max) NULL,
	[WMSLocationIdGoodsInRoute_RU] [nvarchar](max) NULL,
	[VendAccountCustom_RU] [nvarchar](max) NULL,
	[ReportAsFinishedPostingMethod] [nvarchar](max) NULL,
	[UnderdeliveryWarehouseId] [nvarchar](max) NULL,
	[GoodsInTransitWarehouseId] [nvarchar](max) NULL,
	[ExternalWarehouseDefaultLocationId] [nvarchar](max) NULL,
	[ExternalWarehouseManagementSystemId] [nvarchar](max) NULL,
	[ExternalWarehouseId] [nvarchar](max) NULL,
	[IsWarehouseExternallyManaged] [nvarchar](max) NULL
) ON [PRIMARY] TEXTIMAGE_ON [PRIMARY]
GO
/****** Object:  View [dbo].[vw_D365_Sales_Registers]    Script Date: 30/07/2025 12:27:44 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO


create view [dbo].[vw_D365_Sales_Registers]
as
SELECT [InventoryLotId]
      ,[RequestedReceiptDate]
      ,[bill_time]
      ,[transaction_date]
      ,[SalesOrderLineStatus]
      ,[Product Id]
      ,[Batch Key]
      ,[Contact No]
      ,[Location Id]
      ,[Gift Card No]
      ,[Discount Amount]
      ,[Batch]
      ,[Unit]
      ,[Qty Sold]
      ,[CalculateLineAmount]
      ,[LineDescription]
      ,[Bill No]
      ,[Discount %]
      ,[SalesPrice]
      ,[Line Number]
      ,[Source Details]
      ,[Line Amount]
      ,[Tax Amount]
      ,[SalesPriceQuantity]
      ,[Tax Group]
      ,[RequestedShippingDate]
      ,[Member Address]
      ,[Customer Id]
      ,[Payment Mode]
      ,[Salesman Id]
      ,[Agent Name]
      ,[Prepared by]
      ,[Driver]
      ,[Order source]
      ,[Customer Group]
      ,[With Insurance]
      ,[Backend Customer Id]
      ,[cost_amount_retail]
      ,[discount_reason]
      ,[doctor_code]
      ,[Retail Promo Cost]
      ,[Retail Qty Sold]
      ,[Retail Price]
      ,[discount_offer_id]
      ,[Discount Name]
      ,[member_id]
      ,[partner_name]
      ,[DiscountOriginType]
      ,[trx_id]
      ,[ReceiptNumber]
      ,[Card No]
      ,[source_crm]
      ,[insurance_claim_no]
      ,[insurance_card_no]
  FROM [192.168.60.2].[d365].[dbo].[vw_Sales_Registers]
GO
/****** Object:  View [dbo].[vw_SALES_ZERO_STOCK_REF_COMBINED_30days]    Script Date: 30/07/2025 12:27:44 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO









create view [dbo].[vw_SALES_ZERO_STOCK_REF_COMBINED_30days]
as
SELECT  [ItemNumber]
		
		 ,[LocationID]
      ,sum([Qty_Sold]) [Qty_Sold]
   
    
     
     
  FROM [192.168.70.97].MarinaDashboard.[dbo].[SALES_ZERO_STOCK_REF_COMBINED]
  where billdate>=convert(date,getdate()- 30,8) 
  group by [ItemNumber]
		
		 ,[LocationID]
GO
/****** Object:  View [dbo].[vw_SALES_ZERO_STOCK_REF_COMBINED_6mos]    Script Date: 30/07/2025 12:27:44 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO








create view [dbo].[vw_SALES_ZERO_STOCK_REF_COMBINED_6mos]
as
SELECT  [ItemNumber]
		
		 ,[LocationID]
      ,sum([Qty_Sold]) [Qty_Sold]
   
    
     
     
  FROM [192.168.70.97].MarinaDashboard.[dbo].[SALES_ZERO_STOCK_REF_COMBINED]
  where billdate>=convert(date,getdate()- 181,8) 
  group by [ItemNumber]
		
		 ,[LocationID]
GO
/****** Object:  View [dbo].[vw_Unposted_Sales_Invoice]    Script Date: 30/07/2025 12:27:44 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO



create view [dbo].[vw_Unposted_Sales_Invoice]
as
SELECT [ItemNumber]

      ,[ShippingWarehouseId] SiteCode
     
      
      ,sum([OrderedSalesQuantity]) Qty
     
  FROM [192.168.70.86].[d365].[dbo].[fSalesOrderDetails]
  where [SalesOrderLineStatus]<>'Invoiced' and [OrderedSalesQuantity]<>0
  group by  [ItemNumber]

      ,[ShippingWarehouseId]
     
GO
/****** Object:  StoredProcedure [dbo].[ConvertDate]    Script Date: 30/07/2025 12:27:44 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO

CREATE PROCEDURE [dbo].[ConvertDate]
    @inputDate NVARCHAR(4)
AS
BEGIN
    DECLARE @month NVARCHAR(2), @day NVARCHAR(2), @year NVARCHAR(4)

    SET @month = LEFT(@inputDate, 2)
    SET @day = RIGHT(@inputDate, 2)
    SET @year = CONVERT(NVARCHAR(4), YEAR(GETDATE())) + RIGHT(@inputDate, 2)

    SELECT CONVERT(DATE, @year + '-' + @month + '-' + @day) AS ConvertedDate
END
GO
/****** Object:  StoredProcedure [dbo].[create_Branch_Replenishment_View]    Script Date: 30/07/2025 12:27:44 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO












CREATE PROCEDURE [dbo].[create_Branch_Replenishment_View] 
    @salesDays INT,
    @req_days INT
AS
BEGIN


drop table dbo.Branch_Replenishment_Cons_Sum

SELECT  [ItemNumber]
		
		 ,[LocationID]
      ,sum([Qty_Sold]) [Qty_Sold]
   
     into dbo.Branch_Replenishment_Cons_Sum

  FROM [MarinaDynamics365].[dbo].[SALES_ZERO_STOCK_REF_COMBINED]
  where billdate>=convert(date,getdate()- @salesDays,8) 
  group by [ItemNumber]
		 ,[LocationID]


drop table dbo.Branch_Replenishment_Max_QtySold

SELECT 
    [ItemNumber],
    MAX([Qty_Sold]) AS Max_Qty_Sold,
    [LocationID]
	INTO dbo.Branch_Replenishment_Max_QtySold
FROM 
    [MarinaDynamics365].[dbo].[SALES_ZERO_STOCK_REF_COMBINED]
WHERE 
    [Billdate] >= DATEADD(DAY, - @salesDays, GETDATE())
GROUP BY 
    [ItemNumber],
    [LocationID];


    -- Check if the view exists and drop it if necessary
    IF OBJECT_ID('dbo.vw_Branch_Replenisment_final_view', 'V') IS NOT NULL
        DROP VIEW dbo.vw_Branch_Replenisment_final_view;
    
    -- Use dynamic SQL to create the view
    DECLARE @sql NVARCHAR(MAX);

    SET @sql = N'
    CREATE VIEW dbo.vw_Branch_Replenisment_final_view AS
    SELECT 
        loc.STORECODE, 
        loc.ItemNumber, 
        loc.ShortName, 
        loc.ProductName, 
        loc.ProductGroupId, 
        ISNULL(brc.Qty_Sold, 0) AS Cos, 
        ISNULL(dbs.Stock, 0) AS Stock, 
        ISNULL(dbs.Ordered, 0) AS Intransit, 
        ISNULL(dbs.Stock, 0) + ISNULL(dbs.Ordered, 0) AS TotalStock, 
        ISNULL(wh.Stock, 0) AS WHStock, 
        ISNULL(wh.Ordered, 0) AS WHInTransit, 
        round(ISNULL(brc.Qty_Sold, 0) / ' + CAST(@salesDays AS NVARCHAR) + N' * ' + CAST(@req_days AS NVARCHAR) + N' 
            - (ISNULL(dbs.Stock, 0) + ISNULL(dbs.Ordered, 0)),0) AS Req_Order, 
			      ISNULL(brc.Qty_Sold, 0) / ' + CAST(@salesDays AS NVARCHAR) + N' * ' + CAST(@req_days AS NVARCHAR) + N' 
            - (ISNULL(dbs.Stock, 0) + ISNULL(dbs.Ordered, 0)) AS Req_Order_raw, 
        pm.Selling_Price, 
        ISNULL(brm.Max_Qty_Sold, 0) AS MaxQtySold, 
        ISNULL(tolr.ReceivedQuantity, 0) AS Last_Rec_Qty, 
        tolr.RequestedReceiptDate AS Last_Rec_Date,
        ' + CAST(@req_days AS NVARCHAR) + N' AS [Req. Days],
	          ISNULL(dbo.Mx_Min_Max_Raw_Upload.Min, ''0'') AS Min, ISNULL(dbo.Mx_Min_Max_Raw_Upload.Max, ''0'') AS Max
			    , dbo.Lastest_Sales_per_item_Branch.Billdate AS Last_Sales_date, dbo.Lastest_Sales_per_item_Branch.Qty_Sold AS Last_Sales_qty
						  , dbo.TransferOrderLines_Pending_InBR2WH_Transit_SUM.Qty as br2wh_Instransit, dbo.PurchaseOrder_Status_sum.RequestedDeliveryDate AS Pending_LPO_Date
						  , ISNULL(dbo.PurchaseOrder_Status_sum.OrderedPurchaseQuantity, 0) AS Pending_LPO_Qty
						  , ISNULL(dbo.PurchaseOrder_Status_sum.Remaining, 0) AS Pending_LPO_Qty_Lacking
						  ,dbo.TransferOrder_Pending_Sum_created.Pending_Qty AS TO_Created
						  , dbo.TransferOrder_Pending_Sum_shipped.Pending_Qty AS TO_Shifted    FROM 
        dbo.Mx_Product_Master_new_w_location AS loc
        INNER JOIN dbo.Mx_PriceMaster AS pm ON loc.ItemNumber = pm.Item
		LEFT OUTER JOIN
                         dbo.TransferOrder_Pending_Sum_shipped ON loc.STORECODE = dbo.TransferOrder_Pending_Sum_shipped.ReceivingWarehouseId AND 
                         loc.ItemNumber = dbo.TransferOrder_Pending_Sum_shipped.ItemNumber LEFT OUTER JOIN
                         dbo.TransferOrder_Pending_Sum_created ON loc.STORECODE = dbo.TransferOrder_Pending_Sum_created.ReceivingWarehouseId AND 
                         loc.ItemNumber = dbo.TransferOrder_Pending_Sum_created.ItemNumber
		 LEFT OUTER JOIN
                         dbo.PurchaseOrder_Status_sum ON loc.ItemNumber = dbo.PurchaseOrder_Status_sum.ItemNumber
		LEFT OUTER JOIN
                         dbo.TransferOrderLines_Pending_InBR2WH_Transit_SUM ON loc.ItemNumber = dbo.TransferOrderLines_Pending_InBR2WH_Transit_SUM.ItemNumber
		LEFT OUTER JOIN
                         dbo.Lastest_Sales_per_item_Branch ON loc.ItemNumber = dbo.Lastest_Sales_per_item_Branch.ItemNumber AND loc.LocationID = dbo.Lastest_Sales_per_item_Branch.LocationID 
		LEFT OUTER JOIN
                         dbo.Mx_Min_Max_Raw_Upload ON loc.ItemNumber = dbo.Mx_Min_Max_Raw_Upload.ItemNumber AND loc.STORECODE = dbo.Mx_Min_Max_Raw_Upload.SiteCode 
        LEFT JOIN dbo.TransferOrders_Latest_Received AS tolr 
            ON loc.ItemNumber = tolr.ItemNumber 
            AND loc.STORECODE = tolr.ReceivingWarehouseId
        LEFT JOIN dbo.Branch_Replenishment_Max_QtySold AS brm 
            ON loc.ItemNumber = brm.ItemNumber 
            AND loc.LocationID = brm.LocationID
        LEFT JOIN dbo.vw_Drug_Batch_Stock_ordered_SUM_PUR_WH AS wh 
            ON loc.ItemNumber = wh.ItemNumber
        LEFT JOIN dbo.Drug_Batch_Stock_ordered_SUM_PUR AS dbs 
            ON loc.ItemNumber = dbs.ItemNumber 
            AND loc.LocationID = dbs.LocationID
        LEFT JOIN dbo.Branch_Replenishment_Cons_Sum AS brc 
            ON loc.ItemNumber = brc.ItemNumber AND loc.LocationID = brc.LocationID
    WHERE loc.STORECODE NOT IN (''WH0001'', ''WH0002'')AND loc.ProductGroupId in ( SELECT  [Column1]
   FROM [MarinaDynamics365].[dbo].[Branch_Replenishment_Category]);
    ';

 
	   EXEC sp_executesql @sql;
END;

GO
/****** Object:  StoredProcedure [dbo].[create_Branch_Replenishment_View_Items_Branch_selected]    Script Date: 30/07/2025 12:27:44 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO










CREATE PROCEDURE [dbo].[create_Branch_Replenishment_View_Items_Branch_selected] 
    @salesDays INT,
    @req_days INT
AS
BEGIN


drop table dbo.Branch_Replenishment_Cons_Sum

SELECT  [ItemNumber]
		
		 ,[LocationID]
      ,sum([Qty_Sold]) [Qty_Sold]
   
     into dbo.Branch_Replenishment_Cons_Sum

  FROM [MarinaDynamics365].[dbo].[SALES_ZERO_STOCK_REF_COMBINED]
  where billdate>=convert(date,getdate()- @salesDays,8) 
  group by [ItemNumber]
		 ,[LocationID]


drop table dbo.Branch_Replenishment_Max_QtySold

SELECT 
    [ItemNumber],
    MAX([Qty_Sold]) AS Max_Qty_Sold,
    [LocationID]
	INTO dbo.Branch_Replenishment_Max_QtySold
FROM 
    [MarinaDynamics365].[dbo].[SALES_ZERO_STOCK_REF_COMBINED]
WHERE 
    [Billdate] >= DATEADD(DAY, - @salesDays, GETDATE())
GROUP BY 
    [ItemNumber],
    [LocationID];


    -- Check if the view exists and drop it if necessary
    IF OBJECT_ID('dbo.vw_Branch_Replenisment_final_view_Items_Branch_selected', 'V') IS NOT NULL
        DROP VIEW dbo.vw_Branch_Replenisment_final_view_Items_Branch_selected;
    
    -- Use dynamic SQL to create the view
    DECLARE @sql NVARCHAR(MAX);

    SET @sql = N'
    CREATE VIEW dbo.vw_Branch_Replenisment_final_view_Items_Branch_selected AS
    SELECT 
        loc.STORECODE, 
        loc.ItemNumber, 
        loc.ShortName, 
        loc.ProductName, 
        loc.ProductGroupId, 
        ISNULL(brc.Qty_Sold, 0) AS Cos, 
        ISNULL(dbs.Stock, 0) AS Stock, 
        ISNULL(dbs.Ordered, 0) AS Intransit, 
        ISNULL(dbs.Stock, 0) + ISNULL(dbs.Ordered, 0) AS TotalStock, 
        ISNULL(wh.Stock, 0) AS WHStock, 
        ISNULL(wh.Ordered, 0) AS WHInTransit, 
        round(ISNULL(brc.Qty_Sold, 0) / ' + CAST(@salesDays AS NVARCHAR) + N' * ' + CAST(@req_days AS NVARCHAR) + N' 
            - (ISNULL(dbs.Stock, 0) + ISNULL(dbs.Ordered, 0)),0) AS Req_Order, 
			      ISNULL(brc.Qty_Sold, 0) / ' + CAST(@salesDays AS NVARCHAR) + N' * ' + CAST(@req_days AS NVARCHAR) + N' 
            - (ISNULL(dbs.Stock, 0) + ISNULL(dbs.Ordered, 0)) AS Req_Order_raw, 

        pm.Selling_Price, 
        ISNULL(brm.Max_Qty_Sold, 0) AS MaxQtySold, 
        ISNULL(tolr.ReceivedQuantity, 0) AS Last_Rec_Qty, 
        tolr.RequestedReceiptDate AS Last_Rec_Date,
        ' + CAST(@req_days AS NVARCHAR) + N' AS [Req. Days],
	          ISNULL(dbo.Mx_Min_Max_Raw_Upload.Min, ''0'') AS Min, ISNULL(dbo.Mx_Min_Max_Raw_Upload.Max, ''0'') AS Max
			    , dbo.Lastest_Sales_per_item_Branch.Billdate AS Last_Sales_date, 
                         dbo.Lastest_Sales_per_item_Branch.Qty_Sold AS Last_Sales_qty
						  , dbo.TransferOrderLines_Pending_InBR2WH_Transit_SUM.Qty as br2wh_Instransit
						  , dbo.PurchaseOrder_Status_sum.RequestedDeliveryDate AS Pending_LPO_Date
						  , ISNULL(dbo.PurchaseOrder_Status_sum.OrderedPurchaseQuantity, 0) AS Pending_LPO_Qty
						    , ISNULL(dbo.PurchaseOrder_Status_sum.Remaining, 0) AS Pending_LPO_Qty_Lacking
				

    FROM 
        dbo.Mx_Product_Master_new_w_location AS loc
        INNER JOIN dbo.Mx_PriceMaster AS pm ON loc.ItemNumber = pm.Item
		
		 LEFT OUTER JOIN
                         dbo.PurchaseOrder_Status_sum ON loc.ItemNumber = dbo.PurchaseOrder_Status_sum.ItemNumber
		LEFT OUTER JOIN
                         dbo.TransferOrderLines_Pending_InBR2WH_Transit_SUM ON loc.ItemNumber = dbo.TransferOrderLines_Pending_InBR2WH_Transit_SUM.ItemNumber
		LEFT OUTER JOIN
                         dbo.Lastest_Sales_per_item_Branch ON loc.ItemNumber = dbo.Lastest_Sales_per_item_Branch.ItemNumber AND loc.LocationID = dbo.Lastest_Sales_per_item_Branch.LocationID 

		LEFT OUTER JOIN
                         dbo.Mx_Min_Max_Raw_Upload ON loc.ItemNumber = dbo.Mx_Min_Max_Raw_Upload.ItemNumber AND loc.STORECODE = dbo.Mx_Min_Max_Raw_Upload.SiteCode 
        LEFT JOIN dbo.TransferOrders_Latest_Received AS tolr 
            ON loc.ItemNumber = tolr.ItemNumber 
            AND loc.STORECODE = tolr.ReceivingWarehouseId
        LEFT JOIN dbo.Branch_Replenishment_Max_QtySold AS brm 
            ON loc.ItemNumber = brm.ItemNumber 
            AND loc.LocationID = brm.LocationID
        LEFT JOIN dbo.vw_Drug_Batch_Stock_ordered_SUM_PUR_WH AS wh 
            ON loc.ItemNumber = wh.ItemNumber
        LEFT JOIN dbo.Drug_Batch_Stock_ordered_SUM_PUR AS dbs 
            ON loc.ItemNumber = dbs.ItemNumber 
            AND loc.LocationID = dbs.LocationID
        LEFT JOIN dbo.Branch_Replenishment_Cons_Sum AS brc 
            ON loc.ItemNumber = brc.ItemNumber 
            AND loc.LocationID = brc.LocationID
    WHERE 
        loc.STORECODE NOT IN (''WH0001'', ''WH0002'')
        AND loc.ItemNumber in ( SELECT  [Column1]
     
  FROM [MarinaDynamics365].[dbo].[Branch_Replenishment_itemnumberList])

 AND loc.ShortName in ( SELECT  [Column1]
     
  FROM [MarinaDynamics365].[dbo].[Branch_Replenishment_branch]);
    ';

    EXEC sp_executesql @sql;
END;

GO
/****** Object:  StoredProcedure [dbo].[create_Branch_Replenishment_View_Items_Branch_upload]    Script Date: 30/07/2025 12:27:44 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO












CREATE PROCEDURE [dbo].[create_Branch_Replenishment_View_Items_Branch_upload] 
    @salesDays INT,
    @req_days INT
AS
BEGIN


drop table dbo.Branch_Replenishment_Cons_Sum

SELECT  [ItemNumber]
		
		 ,[LocationID]
      ,sum([Qty_Sold]) [Qty_Sold]
   
     into dbo.Branch_Replenishment_Cons_Sum

  FROM [MarinaDynamics365].[dbo].[SALES_ZERO_STOCK_REF_COMBINED]
  where billdate>=convert(date,getdate()- @salesDays,8) 
  group by [ItemNumber]
		 ,[LocationID]


drop table dbo.Branch_Replenishment_Max_QtySold

SELECT 
    [ItemNumber],
    MAX([Qty_Sold]) AS Max_Qty_Sold,
    [LocationID]
	INTO dbo.Branch_Replenishment_Max_QtySold
FROM 
    [MarinaDynamics365].[dbo].[SALES_ZERO_STOCK_REF_COMBINED]
WHERE 
    [Billdate] >= DATEADD(DAY, - @salesDays, GETDATE())
GROUP BY 
    [ItemNumber],
    [LocationID];


    -- Check if the view exists and drop it if necessary
    IF OBJECT_ID('dbo.vw_Branch_Replenisment_final_view_Items_Branch_upload', 'V') IS NOT NULL
        DROP VIEW dbo.vw_Branch_Replenisment_final_view_Items_Branch_upload;
    
    -- Use dynamic SQL to create the view
    DECLARE @sql NVARCHAR(MAX);

    SET @sql = N'
    CREATE VIEW dbo.vw_Branch_Replenisment_final_view_Items_Branch_upload AS
    SELECT 
        loc.STORECODE, 
        loc.ItemNumber, 
        loc.ShortName, 
        loc.ProductName, 
        loc.ProductGroupId, 
        ISNULL(brc.Qty_Sold, 0) AS Cos, 
        ISNULL(dbs.Stock, 0) AS Stock, 
        ISNULL(dbs.Ordered, 0) AS Intransit, 
        ISNULL(dbs.Stock, 0) + ISNULL(dbs.Ordered, 0) AS TotalStock, 
        ISNULL(wh.Stock, 0) AS WHStock, 
        ISNULL(wh.Ordered, 0) AS WHInTransit, 
        round(ISNULL(brc.Qty_Sold, 0) / ' + CAST(@salesDays AS NVARCHAR) + N' * ' + CAST(@req_days AS NVARCHAR) + N' 
            - (ISNULL(dbs.Stock, 0) + ISNULL(dbs.Ordered, 0)),0) AS Req_Order, 
			      ISNULL(brc.Qty_Sold, 0) / ' + CAST(@salesDays AS NVARCHAR) + N' * ' + CAST(@req_days AS NVARCHAR) + N' 
            - (ISNULL(dbs.Stock, 0) + ISNULL(dbs.Ordered, 0)) AS Req_Order_raw, 

        pm.Selling_Price, 
        ISNULL(brm.Max_Qty_Sold, 0) AS MaxQtySold, 
        ISNULL(tolr.ReceivedQuantity, 0) AS Last_Rec_Qty, 
        tolr.RequestedReceiptDate AS Last_Rec_Date,
        ' + CAST(@req_days AS NVARCHAR) + N' AS [Req. Days],
	          ISNULL(dbo.Mx_Min_Max_Raw_Upload.Min, ''0'') AS Min, ISNULL(dbo.Mx_Min_Max_Raw_Upload.Max, ''0'') AS Max
			    , dbo.Lastest_Sales_per_item_Branch.Billdate AS Last_Sales_date, 
                         dbo.Lastest_Sales_per_item_Branch.Qty_Sold AS Last_Sales_qty
						  , dbo.TransferOrderLines_Pending_InBR2WH_Transit_SUM.Qty as br2wh_Instransit
						  , dbo.PurchaseOrder_Status_sum.RequestedDeliveryDate AS Pending_LPO_Date
						  , ISNULL(dbo.PurchaseOrder_Status_sum.OrderedPurchaseQuantity, 0) AS Pending_LPO_Qty
						    , ISNULL(dbo.PurchaseOrder_Status_sum.Remaining, 0) AS Pending_LPO_Qty_Lacking
   FROM 
        dbo.Mx_Product_Master_new_w_location AS loc
        INNER JOIN dbo.Mx_PriceMaster AS pm ON loc.ItemNumber = pm.Item
			LEFT OUTER JOIN
                         dbo.TransferOrder_Pending_Sum_shipped ON loc.STORECODE = dbo.TransferOrder_Pending_Sum_shipped.ReceivingWarehouseId AND 
                         loc.ItemNumber = dbo.TransferOrder_Pending_Sum_shipped.ItemNumber LEFT OUTER JOIN
                         dbo.TransferOrder_Pending_Sum_created ON loc.STORECODE = dbo.TransferOrder_Pending_Sum_created.ReceivingWarehouseId AND 
                         loc.ItemNumber = dbo.TransferOrder_Pending_Sum_created.ItemNumber
		 LEFT OUTER JOIN
                         dbo.PurchaseOrder_Status_sum ON loc.ItemNumber = dbo.PurchaseOrder_Status_sum.ItemNumber
		LEFT OUTER JOIN
                         dbo.TransferOrderLines_Pending_InBR2WH_Transit_SUM ON loc.ItemNumber = dbo.TransferOrderLines_Pending_InBR2WH_Transit_SUM.ItemNumber
		LEFT OUTER JOIN
                         dbo.Lastest_Sales_per_item_Branch ON loc.ItemNumber = dbo.Lastest_Sales_per_item_Branch.ItemNumber AND loc.LocationID = dbo.Lastest_Sales_per_item_Branch.LocationID 

		LEFT OUTER JOIN
                         dbo.Mx_Min_Max_Raw_Upload ON loc.ItemNumber = dbo.Mx_Min_Max_Raw_Upload.ItemNumber AND loc.STORECODE = dbo.Mx_Min_Max_Raw_Upload.SiteCode 
        LEFT JOIN dbo.TransferOrders_Latest_Received AS tolr 
            ON loc.ItemNumber = tolr.ItemNumber 
            AND loc.STORECODE = tolr.ReceivingWarehouseId
        LEFT JOIN dbo.Branch_Replenishment_Max_QtySold AS brm 
            ON loc.ItemNumber = brm.ItemNumber 
            AND loc.LocationID = brm.LocationID
        LEFT JOIN dbo.vw_Drug_Batch_Stock_ordered_SUM_PUR_WH AS wh 
            ON loc.ItemNumber = wh.ItemNumber
        LEFT JOIN dbo.Drug_Batch_Stock_ordered_SUM_PUR AS dbs 
            ON loc.ItemNumber = dbs.ItemNumber 
            AND loc.LocationID = dbs.LocationID
        LEFT JOIN dbo.Branch_Replenishment_Cons_Sum AS brc 
            ON loc.ItemNumber = brc.ItemNumber 
            AND loc.LocationID = brc.LocationID
    WHERE 
        loc.STORECODE NOT IN (''WH0001'', ''WH0002'')
		 AND loc.ShortName in ( SELECT  dbo.udftrim([Column1])
     
  FROM [MarinaDynamics365].[dbo].[Branch_Replenishment_branch] )

        AND loc.ItemNumber in ( SELECT  [Column1]
     
  FROM [MarinaDynamics365].[dbo].[Branch_Replenishment_itemnumberList])

    ';

    EXEC sp_executesql @sql;
END;

GO
/****** Object:  StoredProcedure [dbo].[create_Branch_Replenishment_View_Order]    Script Date: 30/07/2025 12:27:44 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO










CREATE PROCEDURE [dbo].[create_Branch_Replenishment_View_Order] 
    @salesDays INT,
    @req_days INT
AS
BEGIN

drop table dbo.Branch_Replenishment_Cons_Sum_Total

SELECT  [ItemNumber]
		
		 
      ,sum([Qty_Sold]) [Qty_Sold]
   
     into dbo.Branch_Replenishment_Cons_Sum_Total

  FROM [MarinaDynamics365].[dbo].[SALES_ZERO_STOCK_REF_COMBINED]
  where billdate>=convert(date,getdate()- @salesDays,8) 
  group by [ItemNumber]


    -- Check if the view exists and drop it if necessary
    IF OBJECT_ID('dbo.vw_Branch_Replenisment_final_view_Order', 'V') IS NOT NULL
        DROP VIEW dbo.vw_Branch_Replenisment_final_view_Order;
    
    -- Use dynamic SQL to create the view
    DECLARE @sql NVARCHAR(MAX);

    SET @sql = N'
    CREATE VIEW dbo.vw_Branch_Replenisment_final_view_Order AS
   SELECT        dbo.Mx_Product_Master_new.ItemNumber, dbo.Mx_Product_Master_new.ProductName, ISNULL(dbo.Drug_Batch_Stock_ordered_SUM_Branch_Total.Stock, 0) AS Stock, 
                         ISNULL(dbo.Drug_Batch_Stock_ordered_SUM_Branch_Total.Ordered, 0) AS InTransit, ISNULL(dbo.Branch_Replenishment_Cons_Sum_Total.Qty_Sold, 0) AS Cons, ISNULL(dbo.Drug_Batch_Stock_ordered_SUM_PUR_WH.Stock, 
                         0) AS WH_Stock, ISNULL(dbo.Drug_Batch_Stock_ordered_SUM_PUR_WH.Ordered, 0) AS WH_InTransit, ISNULL(dbo.Drug_Batch_Stock_ordered_SUM_Branch_Total.Stock, 0) 
                         + ISNULL(dbo.Drug_Batch_Stock_ordered_SUM_Branch_Total.Ordered, 0) + ISNULL(dbo.Drug_Batch_Stock_ordered_SUM_PUR_WH.Stock, 0) + ISNULL(dbo.Drug_Batch_Stock_ordered_SUM_PUR_WH.Ordered, 0) 
                         AS Total_Stock, ISNULL(dbo.Branch_Replenishment_Cons_Sum_Total.Qty_Sold, 0) / ' + CAST(@salesDays AS NVARCHAR) + N' * ' + CAST(@req_days AS NVARCHAR) + N'  - (ISNULL(dbo.Drug_Batch_Stock_ordered_SUM_Branch_Total.Stock, 0) 
                         + ISNULL(dbo.Drug_Batch_Stock_ordered_SUM_Branch_Total.Ordered, 0) + ISNULL(dbo.Drug_Batch_Stock_ordered_SUM_PUR_WH.Stock, 0) + ISNULL(dbo.Drug_Batch_Stock_ordered_SUM_PUR_WH.Ordered, 0)) 
                         AS Req_Order, dbo.Mx_PriceMaster.Selling_Price, ISNULL(dbo.VendorsV2.VendorOrganizationName, N''NO VENDOR ASSIGNED'') AS Vendor
						 ,' + CAST(@salesDays AS NVARCHAR) + N' as Sales_Days
						 ,' + CAST(@req_days AS NVARCHAR) + N' as Req_Days
FROM            dbo.VendorsV2 INNER JOIN
                         dbo.MX_Product_Cost_SPrice_Upload_Raw ON dbo.VendorsV2.VendorAccountNumber = dbo.MX_Product_Cost_SPrice_Upload_Raw.Vendor RIGHT OUTER JOIN
                         dbo.Mx_Product_Master_new ON dbo.MX_Product_Cost_SPrice_Upload_Raw.[Item number] = dbo.Mx_Product_Master_new.ItemNumber LEFT OUTER JOIN
                         dbo.Mx_PriceMaster ON dbo.Mx_Product_Master_new.ItemNumber = dbo.Mx_PriceMaster.Item LEFT OUTER JOIN
                         dbo.Drug_Batch_Stock_ordered_SUM_PUR_WH ON dbo.Mx_Product_Master_new.ItemNumber = dbo.Drug_Batch_Stock_ordered_SUM_PUR_WH.ItemNumber LEFT OUTER JOIN
                         dbo.Branch_Replenishment_Cons_Sum_Total ON dbo.Mx_Product_Master_new.ItemNumber = dbo.Branch_Replenishment_Cons_Sum_Total.ItemNumber LEFT OUTER JOIN
                         dbo.Drug_Batch_Stock_ordered_SUM_Branch_Total ON dbo.Mx_Product_Master_new.ItemNumber = dbo.Drug_Batch_Stock_ordered_SUM_Branch_Total.ItemNumber

    ';

 
	   EXEC sp_executesql @sql;
END;

GO
/****** Object:  StoredProcedure [dbo].[create_Branch_Replenishment_View_orig]    Script Date: 30/07/2025 12:27:44 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO



CREATE PROCEDURE [dbo].[create_Branch_Replenishment_View_orig] 
    @salesDays INT,
    @req_days INT
AS
BEGIN


drop table dbo.Branch_Replenishment_Cons_Sum

SELECT  [ItemNumber]
		
		 ,[LocationID]
      ,sum([Qty_Sold]) [Qty_Sold]
   
     into dbo.Branch_Replenishment_Cons_Sum

  FROM [MarinaDynamics365].[dbo].[SALES_ZERO_STOCK_REF_COMBINED]
  where billdate>=convert(date,getdate()- @salesDays,8) 
  group by [ItemNumber]
		 ,[LocationID]


drop table dbo.Branch_Replenishment_Max_QtySold

SELECT 
    [ItemNumber],
    MAX([Qty_Sold]) AS Max_Qty_Sold,
    [LocationID]
	INTO dbo.Branch_Replenishment_Max_QtySold
FROM 
    [MarinaDynamics365].[dbo].[SALES_ZERO_STOCK_REF_COMBINED]
WHERE 
    [Billdate] >= DATEADD(DAY, - @salesDays, GETDATE())
GROUP BY 
    [ItemNumber],
    [LocationID];


    -- Check if the view exists and drop it if necessary
    IF OBJECT_ID('dbo.vw_Branch_Replenisment_final_view', 'V') IS NOT NULL
        DROP VIEW dbo.vw_Branch_Replenisment_final_view;
    
    -- Use dynamic SQL to create the view
    DECLARE @sql NVARCHAR(MAX);

    SET @sql = N'
    CREATE VIEW dbo.vw_Branch_Replenisment_final_view AS
    SELECT 
        loc.STORECODE, 
        loc.ItemNumber, 
        loc.ShortName, 
        loc.ProductName, 
        loc.ProductGroupId, 
        ISNULL(brc.Qty_Sold, 0) AS Cos, 
        ISNULL(dbs.Stock, 0) AS Stock, 
        ISNULL(dbs.Ordered, 0) AS Intransit, 
        ISNULL(dbs.Stock, 0) + ISNULL(dbs.Ordered, 0) AS TotalStock, 
        ISNULL(wh.Stock, 0) AS WHStock, 
        ISNULL(wh.Ordered, 0) AS WHInTransit, 
        ISNULL(brc.Qty_Sold, 0) / ' + CAST(@salesDays AS NVARCHAR) + N' * ' + CAST(@req_days AS NVARCHAR) + N' 
            - (ISNULL(dbs.Stock, 0) + ISNULL(dbs.Ordered, 0)) AS Req_Order, 
        pm.Selling_Price, 
        ISNULL(brm.Max_Qty_Sold, 0) AS MaxQtySold, 
        ISNULL(tolr.ReceivedQuantity, 0) AS Last_Rec_Qty, 
        tolr.RequestedReceiptDate AS Last_Rec_Date,
        ' + CAST(@req_days AS NVARCHAR) + N' AS [Req. Days]
    FROM 
        dbo.Mx_Product_Master_new_w_location AS loc
        INNER JOIN dbo.Mx_PriceMaster AS pm ON loc.ItemNumber = pm.Item
        LEFT JOIN dbo.TransferOrders_Latest_Received AS tolr 
            ON loc.ItemNumber = tolr.ItemNumber 
            AND loc.STORECODE = tolr.ReceivingWarehouseId
        LEFT JOIN dbo.Branch_Replenishment_Max_QtySold AS brm 
            ON loc.ItemNumber = brm.ItemNumber 
            AND loc.LocationID = brm.LocationID
        LEFT JOIN dbo.vw_Drug_Batch_Stock_ordered_SUM_PUR_WH AS wh 
            ON loc.ItemNumber = wh.ItemNumber
        LEFT JOIN dbo.Drug_Batch_Stock_ordered_SUM_PUR AS dbs 
            ON loc.ItemNumber = dbs.ItemNumber 
            AND loc.LocationID = dbs.LocationID
        LEFT JOIN dbo.Branch_Replenishment_Cons_Sum AS brc 
            ON loc.ItemNumber = brc.ItemNumber 
            AND loc.LocationID = brc.LocationID
    WHERE 
        loc.STORECODE NOT IN (''WH0001'', ''WH0002'')
        AND loc.ProductGroupId in ( SELECT  [Column1]
     
  FROM [MarinaDynamics365].[dbo].[Branch_Replenishment_Category] );
    ';

    EXEC sp_executesql @sql;
END;

GO
/****** Object:  StoredProcedure [dbo].[ExecuteDynamicSQLAndLog]    Script Date: 30/07/2025 12:27:44 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE PROCEDURE [dbo].[ExecuteDynamicSQLAndLog]
    (@SqlDesc NVARCHAR(MAX),@SqlQuery NVARCHAR(MAX))
AS
BEGIN
    DECLARE @ResultMessage NVARCHAR(MAX);
    DECLARE @RowsAffected INT;
	DECLARE @StartTime DATETIME;
    DECLARE @EndTime DATETIME;
    DECLARE @DurationMilliseconds INT;

	SET @StartTime = GETDATE();

    BEGIN TRY
        EXEC sp_executesql @SqlQuery;

		

        SET @RowsAffected = @@ROWCOUNT;
        SET @ResultMessage = 'Success! Query executed successfully. Rows affected: ' + CAST(@RowsAffected AS NVARCHAR(10));
		SET @EndTime = GETDATE();
        SET @DurationMilliseconds = DATEDIFF(SECOND, @StartTime, @EndTime);
    END TRY
    BEGIN CATCH

        SET @RowsAffected = 0;
        SET @ResultMessage = 'Error: ' + ERROR_MESSAGE();
		SET @EndTime = GETDATE();
        SET @DurationMilliseconds = DATEDIFF(SECOND, @StartTime, @EndTime);
    END CATCH

    INSERT INTO dbo.QueryExecutionLog (QueryText, ExecutionDateTime, RowsAffected, ResultMessage,Duration)
    VALUES (@SqlDesc, GETDATE(), @RowsAffected, @ResultMessage,dbo.SecTimeDay(@DurationMilliseconds) );
END;

GO
/****** Object:  StoredProcedure [dbo].[GenerateOrderBonusLinesToDynamics]    Script Date: 30/07/2025 12:27:44 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO









CREATE PROCEDURE [dbo].[GenerateOrderBonusLinesToDynamics](@lpo_last VARCHAR(255))
AS
BEGIN
    DECLARE @ref VARCHAR(255),
	@bonus_flag VARCHAR(255),
	@lpo_last_digit int
	; -- Declare variable to hold the selected reference
	  delete from	[dbo].[FEB2024_MinMax_Order_Branch_Final_for_DynamicsUpload_Final]
    -- Cursor to iterate through the SELECT result
   
	select  @lpo_last_digit=cast(@lpo_last as int)

   DECLARE ref_cursor CURSOR FOR
  
    SELECT [ref] FROM [MarinaDynamics365].[dbo].[FEB2024_MinMax_Order_Branch_Final_for_DynamicsUpload];

    OPEN ref_cursor;

    -- Fetch the first reference
    FETCH NEXT FROM ref_cursor INTO @ref;

    -- Loop through each reference and perform the INSERT
    WHILE @@FETCH_STATUS = 0
	BEGIN

	Select @bonus_flag = case when Bonus=0 then 0 else 1 end
	FROM [MarinaDynamics365].[dbo].[FEB2024_MinMax_Order_Branch_Final_for_DynamicsUpload]
	where ref=@ref;

	if @bonus_flag=0 

	begin

	INSERT INTO [dbo].[FEB2024_MinMax_Order_Branch_Final_for_DynamicsUpload_Final]
           ([Purchase order]
           ,[Line number]
           ,[Item number]
           ,[Quantity]
           ,[Unit]
           ,[Unit price]
           ,[FOC]
           ,[External item number]
           ,[Vendor]
           ,[ref]
		   ,StoreCode)


	  SELECT 'MAR-PO-00000000'  [Purchase order]
       ,100 [Line number]
	   ,[ItemNumber] [Item number]
       ,[To_Order] [Quantity]
       ,'Pack' Unit
	   ,100.00 [Unit price]
	   ,case when [Bonus]=0 then 'No' Else 'Yes' End FOC
       ,'' [External item number]
       ,[Vendor]
       ,[ref]
	,StoreCode
  FROM [MarinaDynamics365].[dbo].[FEB2024_MinMax_Order_Branch_Final_for_DynamicsUpload]
  where ref=@ref;




	end
	else
	begin

	
	INSERT INTO [dbo].[FEB2024_MinMax_Order_Branch_Final_for_DynamicsUpload_Final]
           ([Purchase order]
           ,[Line number]
           ,[Item number]
           ,[Quantity]
           ,[Unit]
           ,[Unit price]
           ,[FOC]
           ,[External item number]
           ,[Vendor]
           ,[ref]
		   ,StoreCode)


	  SELECT 'MAR-PO-00000000'  [Purchase order]
       ,100 [Line number]
	   ,[ItemNumber] [Item number]
       ,[To_Order] [Quantity]
       ,'Pack' Unit
	   ,100.00 [Unit price]
	   ,'No' FOC
       ,'' [External item number]
       ,[Vendor]
       ,[ref]
	   ,StoreCode
	
  FROM [MarinaDynamics365].[dbo].[FEB2024_MinMax_Order_Branch_Final_for_DynamicsUpload]
  where ref=@ref;


  
	INSERT INTO [dbo].[FEB2024_MinMax_Order_Branch_Final_for_DynamicsUpload_Final]
           ([Purchase order]
           ,[Line number]
           ,[Item number]
           ,[Quantity]
           ,[Unit]
           ,[Unit price]
           ,[FOC]
           ,[External item number]
           ,[Vendor]
           ,[ref]
		   ,StoreCode)


	  SELECT 'MAR-PO-000000000'  [Purchase order]
       ,100 [Line number]
	   ,[ItemNumber] [Item number]
       ,Bonus [Quantity]
       ,'Pack' Unit
	   ,100.00 [Unit price]
	   ,'Yes' FOC
       ,'' [External item number]
       ,[Vendor]
       ,[ref]
	,StoreCode
  FROM [MarinaDynamics365].[dbo].[FEB2024_MinMax_Order_Branch_Final_for_DynamicsUpload]
  where ref=@ref;
	
	



	end


	


        -- Fetch the next reference
        FETCH NEXT FROM ref_cursor INTO @ref;
    END

	drop table  dbo.LPO_Final_Order_Upload 

SELECT [Purchase order]
     --  ,ROW_NUMBER() OVER (PARTITION BY [StoreCode]+[vendor] ORDER BY (SELECT NULL))  as  [Line number]
       ,ROW_NUMBER() OVER (PARTITION BY [StoreCode]+[vendor] ORDER BY 
	   (Select [ProductName]
      FROM [MarinaDynamics365].[dbo].[Mx_Product_Master_new] b
       where b.ItemNumber=f.[Item number])
	  
	   ,[Quantity] desc)  as  [Line number]
      ,[Item number]
      ,[Quantity]
      ,(Select [BOMUnitSymbol]
      FROM [MarinaDynamics365].[dbo].[Mx_Product_Master_new] b
       where b.ItemNumber=f.[Item number]) [Unit]
      ,(Select [Price2] FROM [MarinaDynamics365].[dbo].[MX_Product_Cost_SPrice] p
	  where p.[Item number]=f.[Item number])[Unit price]
      ,[FOC]
      ,[External item number]
      ,[Vendor]
      ,[ref]
      ,[StoreCode]
	   ,(Select [Item sales tax group] FROM [MarinaDynamics365].[dbo].[MX_Product_Cost_SPrice] p
	  where p.[Item number]=f.[Item number])[Tax]
	into dbo.LPO_Final_Order_Upload 
      FROM [MarinaDynamics365].[dbo].[FEB2024_MinMax_Order_Branch_Final_for_DynamicsUpload_Final] f


	  drop table dbo.LPO_Final_Order_Header

	  SELECT 
      'MAR-PO-0000' + convert(varchar,ROW_NUMBER() OVER (ORDER BY [StoreCode]) + @lpo_last_digit ) AS [Purchase order]
	  , [Vendor] [Vendor account]
       ,trim([StoreCode]) [Warehouse]
	   ,( SELECT [STORECODE] + '-' + [REGION] + '-' +[DIVISION] +'----'
	   FROM [MarinaDynamics365].[dbo].[Mx_StoreCode] d
	   where d.STORECODE=u.STORECODE) + [Vendor] +'---' [Financial dimensions]
	   ,[Vendor]+[StoreCode] ref
	   into dbo.LPO_Final_Order_Header
       FROM [MarinaDynamics365].[dbo].[LPO_Final_Order_Upload] u
    	group by  [Vendor]
      ,[StoreCode]
	
	  order  by [StoreCode]
     

	 update dbo.LPO_Final_Order_Upload 
	 set [Purchase order]=(select [Purchase order]
	 FROM [MarinaDynamics365].[dbo].[LPO_Final_Order_Header] h
	 where h.ref=dbo.LPO_Final_Order_Upload.[Vendor]+dbo.LPO_Final_Order_Upload.[StoreCode])




    CLOSE ref_cursor;
    DEALLOCATE ref_cursor;
END
GO
/****** Object:  StoredProcedure [dbo].[GenerateOrderBonusLinesToDynamics_OLD]    Script Date: 30/07/2025 12:27:44 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO









CREATE PROCEDURE [dbo].[GenerateOrderBonusLinesToDynamics_OLD](@lpo_last VARCHAR(255))
AS
BEGIN
    DECLARE @ref VARCHAR(255),
	@bonus_flag VARCHAR(255),
	@lpo_last_digit int
	; -- Declare variable to hold the selected reference
	  delete from	[dbo].[FEB2024_MinMax_Order_Branch_Final_for_DynamicsUpload_Final]
    -- Cursor to iterate through the SELECT result
   
	select  @lpo_last_digit=cast(@lpo_last as int)

   DECLARE ref_cursor CURSOR FOR
  
    SELECT [ref] FROM [MarinaDynamics365].[dbo].[FEB2024_MinMax_Order_Branch_Final_for_DynamicsUpload];

    OPEN ref_cursor;

    -- Fetch the first reference
    FETCH NEXT FROM ref_cursor INTO @ref;

    -- Loop through each reference and perform the INSERT
    WHILE @@FETCH_STATUS = 0
	BEGIN

	Select @bonus_flag = case when Bonus=0 then 0 else 1 end
	FROM [MarinaDynamics365].[dbo].[FEB2024_MinMax_Order_Branch_Final_for_DynamicsUpload]
	where ref=@ref;

	if @bonus_flag=0 

	begin

	INSERT INTO [dbo].[FEB2024_MinMax_Order_Branch_Final_for_DynamicsUpload_Final]
           ([Purchase order]
           ,[Line number]
           ,[Item number]
           ,[Quantity]
           ,[Unit]
           ,[Unit price]
           ,[FOC]
           ,[External item number]
           ,[Vendor]
           ,[ref]
		   ,StoreCode)


	  SELECT 'MAR-PO-00000000'  [Purchase order]
       ,100 [Line number]
	   ,[ItemNumber] [Item number]
       ,[To_Order] [Quantity]
       ,'Pack' Unit
	   ,100.00 [Unit price]
	   ,case when [Bonus]=0 then 'No' Else 'Yes' End FOC
       ,'' [External item number]
       ,[Vendor]
       ,[ref]
	,StoreCode
  FROM [MarinaDynamics365].[dbo].[FEB2024_MinMax_Order_Branch_Final_for_DynamicsUpload]
  where ref=@ref;




	end
	else
	begin

	
	INSERT INTO [dbo].[FEB2024_MinMax_Order_Branch_Final_for_DynamicsUpload_Final]
           ([Purchase order]
           ,[Line number]
           ,[Item number]
           ,[Quantity]
           ,[Unit]
           ,[Unit price]
           ,[FOC]
           ,[External item number]
           ,[Vendor]
           ,[ref]
		   ,StoreCode)


	  SELECT 'MAR-PO-00000000'  [Purchase order]
       ,100 [Line number]
	   ,[ItemNumber] [Item number]
       ,[To_Order] [Quantity]
       ,'Pack' Unit
	   ,100.00 [Unit price]
	   ,'No' FOC
       ,'' [External item number]
       ,[Vendor]
       ,[ref]
	   ,StoreCode
	
  FROM [MarinaDynamics365].[dbo].[FEB2024_MinMax_Order_Branch_Final_for_DynamicsUpload]
  where ref=@ref;


  
	INSERT INTO [dbo].[FEB2024_MinMax_Order_Branch_Final_for_DynamicsUpload_Final]
           ([Purchase order]
           ,[Line number]
           ,[Item number]
           ,[Quantity]
           ,[Unit]
           ,[Unit price]
           ,[FOC]
           ,[External item number]
           ,[Vendor]
           ,[ref]
		   ,StoreCode)


	  SELECT 'MAR-PO-000000000'  [Purchase order]
       ,100 [Line number]
	   ,[ItemNumber] [Item number]
       ,Bonus [Quantity]
       ,'Pack' Unit
	   ,100.00 [Unit price]
	   ,'Yes' FOC
       ,'' [External item number]
       ,[Vendor]
       ,[ref]
	,StoreCode
  FROM [MarinaDynamics365].[dbo].[FEB2024_MinMax_Order_Branch_Final_for_DynamicsUpload]
  where ref=@ref;
	
	



	end


	


        -- Fetch the next reference
        FETCH NEXT FROM ref_cursor INTO @ref;
    END

	drop table  dbo.LPO_Final_Order_Upload 

SELECT [Purchase order]
     --  ,ROW_NUMBER() OVER (PARTITION BY [StoreCode]+[vendor] ORDER BY (SELECT NULL))  as  [Line number]
       ,ROW_NUMBER() OVER (PARTITION BY [StoreCode]+[vendor] ORDER BY 
	   (Select [ProductName]
      FROM [MarinaDynamics365].[dbo].[Mx_Product_Master_new] b
       where b.ItemNumber=f.[Item number])
	  
	   ,[Quantity] desc)  as  [Line number]
      ,[Item number]
      ,[Quantity]
      ,(Select [BOMUnitSymbol]
      FROM [MarinaDynamics365].[dbo].[Mx_Product_Master_new] b
       where b.ItemNumber=f.[Item number]) [Unit]
      ,(Select [Price2] FROM [MarinaDynamics365].[dbo].[MX_Product_Cost_SPrice] p
	  where p.[Item number]=f.[Item number])[Unit price]
      ,[FOC]
      ,[External item number]
      ,[Vendor]
      ,[ref]
      ,[StoreCode]
	   ,(Select [Item sales tax group] FROM [MarinaDynamics365].[dbo].[MX_Product_Cost_SPrice] p
	  where p.[Item number]=f.[Item number])[Tax]
	into dbo.LPO_Final_Order_Upload 
      FROM [MarinaDynamics365].[dbo].[FEB2024_MinMax_Order_Branch_Final_for_DynamicsUpload_Final] f


	  drop table dbo.LPO_Final_Order_Header

	  SELECT 
      'MAR-PO-0000' + convert(varchar,ROW_NUMBER() OVER (ORDER BY [StoreCode]) + @lpo_last_digit ) AS [Purchase order]
	  , [Vendor] [Vendor account]
       ,trim([StoreCode]) [Warehouse]
	   ,( SELECT [STORECODE] + '-' + [REGION] + '-' +[DIVISION] +'-----'
	   FROM [MarinaDynamics365].[dbo].[Mx_StoreCode] d
	   where d.STORECODE=u.STORECODE) + [Vendor] +'--' [Financial dimensions]
	   ,[Vendor]+[StoreCode] ref
	   into dbo.LPO_Final_Order_Header
       FROM [MarinaDynamics365].[dbo].[LPO_Final_Order_Upload] u
    	group by  [Vendor]
      ,[StoreCode]
	
	  order  by [StoreCode]
     

	 update dbo.LPO_Final_Order_Upload 
	 set [Purchase order]=(select [Purchase order]
	 FROM [MarinaDynamics365].[dbo].[LPO_Final_Order_Header] h
	 where h.ref=dbo.LPO_Final_Order_Upload.[Vendor]+dbo.LPO_Final_Order_Upload.[StoreCode])




    CLOSE ref_cursor;
    DEALLOCATE ref_cursor;
END
GO
/****** Object:  StoredProcedure [dbo].[GenerateRandomPassword]    Script Date: 30/07/2025 12:27:44 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO

CREATE PROCEDURE [dbo].[GenerateRandomPassword]
AS
BEGIN
    DECLARE @Characters VARCHAR(50) = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
    DECLARE @Password VARCHAR(8) = '';
    DECLARE @Counter INT = 1;

    WHILE @Counter <= 8
    BEGIN
        DECLARE @RandomIndex INT = CEILING(RAND() * LEN(@Characters));
        SET @Password = @Password + SUBSTRING(@Characters, @RandomIndex, 1);
        SET @Counter = @Counter + 1;
    END

    SELECT @Password AS RandomPassword;
END;

GO
/****** Object:  StoredProcedure [dbo].[GetSalesDataForLast7Days]    Script Date: 30/07/2025 12:27:44 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
CREATE PROCEDURE [dbo].[GetSalesDataForLast7Days]
AS
BEGIN
    DECLARE @startDate DATE = DATEADD(DAY, -6, CAST(GETDATE() AS DATE));
    DECLARE @endDate DATE = CAST(GETDATE() AS DATE);

    DECLARE @dateLabels NVARCHAR(MAX) = '';
    DECLARE @pivotColumns NVARCHAR(MAX) = '';

    WHILE @startDate <= @endDate
    BEGIN
        SET @dateLabels = CONCAT(@dateLabels, ', [', CONVERT(NVARCHAR(10), @startDate, 126), ']');
        SET @pivotColumns = CONCAT(@pivotColumns, ', COALESCE(p.[', CONVERT(NVARCHAR(10), @startDate, 126), '], 0) AS [', CONVERT(NVARCHAR(10), @startDate, 126), ']');
        SET @startDate = DATEADD(DAY, 1, @startDate);
    END

    SET @dateLabels = STUFF(@dateLabels, 1, 2, '');
    SET @pivotColumns = STUFF(@pivotColumns, 1, 2, '');

    DECLARE @sql NVARCHAR(MAX) = '
    WITH Last7DaysData AS (
        SELECT 
            cdm.Branch,
            cdm.SalesDate,
            SUM(cdm.Total_Amount) AS TotalAmount
        FROM [MarinaDashboard].[dbo].[Cash_Deposit_Master] cdm
        WHERE cdm.SalesDate >= DATEADD(DAY, -6, CAST(GETDATE() AS DATE))
        GROUP BY cdm.Branch, cdm.SalesDate
    ),
    PivotedData AS (
        SELECT 
            Branch' + @dateLabels + '
        FROM (
            SELECT 
                lsd.Branch,
                lsd.SalesDate,
                lsd.TotalAmount
            FROM Last7DaysData lsd
        ) AS SourceTable
        PIVOT (
            SUM(TotalAmount)
            FOR SalesDate IN (' + @dateLabels + ')
        ) AS PivotTable
    )
    SELECT 
        b.branch,
        ' + @pivotColumns + '
    FROM [MarinaDashboard].[dbo].[Mx_storecode] b
    LEFT JOIN PivotedData p ON b.branch = p.Branch
    ORDER BY b.branch;
    ';

    EXEC sp_executesql @sql;
END;

GO
/****** Object:  StoredProcedure [dbo].[Insert_PurchaseOrderHeadersV2]    Script Date: 30/07/2025 12:27:44 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO






CREATE PROCEDURE [dbo].[Insert_PurchaseOrderHeadersV2]
AS
BEGIN
  INSERT INTO [dbo].[PurchaseOrderHeadersV2]
           ([dataAreaId]
           ,[PurchaseOrderNumber]
           ,[ExpectedStoreAvailableSalesDate]
           ,[VendorInvoiceDeclarationId]
           ,[DeliveryModeId]
           ,[InvoiceAddressStreet]
           ,[OrderVendorAccountNumber]
           ,[Email]
           ,[TransportationModeId]
           ,[IsChangeManagementActive]
           ,[AccountingDistributionTemplateName]
           ,[DeliveryAddressDescription]
           ,[VendorTransactionSettlementType]
           ,[DeliveryCityInKana]
           ,[DeliveryStreetInKana]
           ,[ReasonComment]
           ,[NumberSequenceGroupId]
           ,[TransportationTemplateId]
           ,[AccountingDate]
           ,[CashDiscountPercentage]
           ,[PurchaseOrderName]
           ,[RequestedDeliveryDate]
           ,[DeliveryAddressCountryRegionId]
           ,[DeliveryAddressLatitude]
           ,[MultilineDiscountVendorGroupCode]
           ,[DeliveryAddressCity]
           ,[ConfirmedDeliveryDate]
           ,[PurchaseRebateVendorGroupId]
           ,[InvoiceAddressCounty]
           ,[ChargeVendorGroupId]
           ,[RequesterPersonnelNumber]
           ,[ProjectId]
           ,[ShippingCarrierId]
           ,[TotalDiscountPercentage]
           ,[DeliveryAddressDistrictName]
           ,[PriceVendorGroupCode]
           ,[PurchaseOrderHeaderCreationMethod]
           ,[DeliveryAddressCountyId]
           ,[DeliveryAddressZipCode]
           ,[IsConsolidatedInvoiceTarget]
           ,[ConfirmingPurchaseOrderCode]
           ,[LanguageId]
           ,[ReasonCode]
           ,[DeliveryAddressDunsNumber]
           ,[DeliveryTermsId]
           ,[BankDocumentType]
           ,[ExpectedStoreReceiptDate]
           ,[DeliveryAddressName]
           ,[InvoiceAddressCountryRegionId]
           ,[ReplenishmentServiceCategoryId]
           ,[PurchaseOrderPoolId]
           ,[DeliveryAddressStreetNumber]
           ,[RequestedShipDate]
           ,[ExpectedCrossDockingDate]
           ,[InvoiceAddressStreetNumber]
           ,[IsDeliveryAddressPrivate]
           ,[TaxExemptNumber]
           ,[FormattedInvoiceAddress]
           ,[BuyerGroupId]
           ,[DeliveryAddressCountryRegionISOCode]
           ,[CashDiscountCode]
           ,[PaymentScheduleName]
           ,[IntrastatTransactionCode]
           ,[URL]
           ,[CurrencyCode]
           ,[ConfirmingPurchaseOrderCodeLanguageId]
           ,[InvoiceType]
           ,[ArePricesIncludingSalesTax]
           ,[DeliveryAddressLocationId]
           ,[GSTSelfBilledInvoiceApprovalNumber]
           ,[IsDeliveredDirectly]
           ,[ConfirmedShipDate]
           ,[ShipCalendarId]
           ,[IntrastatStatisticsProcedureCode]
           ,[InvoiceVendorAccountNumber]
           ,[OverrideSalesTax]
           ,[DeliveryAddressStreet]
           ,[VendorOrderReference]
           ,[ReplenishmentWarehouseId]
           ,[FixedDueDate]
           ,[TransportationDocumentLineId]
           ,[SalesTaxGroupCode]
           ,[IsDeliveryAddressOrderSpecific]
           ,[VendorPostingProfileId]
           ,[VendorPaymentMethodSpecificationName]
           ,[InvoiceAddressCity]
           ,[ShippingCarrierServiceGroupId]
           ,[ContactPersonId]
           ,[DefaultReceivingWarehouseId]
           ,[EUSalesListCode]
           ,[ImportDeclarationNumber]
           ,[PurchaseOrderStatus]
           ,[PaymentTermsName]
           ,[DeliveryAddressLongitude]
           ,[DocumentApprovalStatus]
           ,[InvoiceAddressZipCode]
           ,[ShippingCarrierServiceId]
           ,[DefaultLedgerDimensionDisplayValue]
           ,[DeliveryAddressTimeZone]
           ,[AttentionInformation]
           ,[DeliveryAddressStateId]
           ,[DeliveryBuildingCompliment]
           ,[IntrastatTransportModeCode]
           ,[DeliveryAddressPostBox]
           ,[IsOneTimeVendor]
           ,[IntrastatPortId]
           ,[OrdererPersonnelNumber]
           ,[VendorPaymentMethodName]
           ,[InvoiceAddressState]
           ,[DefaultReceivingSiteId]
           ,[LineDiscountVendorGroupCode]
           ,[TransportationRoutePlanId]
           ,[ZakatContractNumber]
           ,[FormattedDeliveryAddress]
           ,[TotalDiscountVendorGroupCode]
           ,[TradeEndCustomerAccount]
           ,[FiscalDocumentOperationTypeId])

  SELECT [dataAreaId]
      ,[PurchaseOrderNumber]
      ,[ExpectedStoreAvailableSalesDate]
      ,[VendorInvoiceDeclarationId]
      ,[DeliveryModeId]
      ,[InvoiceAddressStreet]
      ,[OrderVendorAccountNumber]
      ,[Email]
      ,[TransportationModeId]
      ,[IsChangeManagementActive]
      ,[AccountingDistributionTemplateName]
      ,[DeliveryAddressDescription]
      ,[VendorTransactionSettlementType]
      ,[DeliveryCityInKana]
      ,[DeliveryStreetInKana]
      ,[ReasonComment]
      ,[NumberSequenceGroupId]
      ,[TransportationTemplateId]
      ,[AccountingDate]
      ,[CashDiscountPercentage]
      ,[PurchaseOrderName]
      ,[RequestedDeliveryDate]
      ,[DeliveryAddressCountryRegionId]
      ,[DeliveryAddressLatitude]
      ,[MultilineDiscountVendorGroupCode]
      ,[DeliveryAddressCity]
      ,[ConfirmedDeliveryDate]
      ,[PurchaseRebateVendorGroupId]
      ,[InvoiceAddressCounty]
      ,[ChargeVendorGroupId]
      ,[RequesterPersonnelNumber]
      ,[ProjectId]
      ,[ShippingCarrierId]
      ,[TotalDiscountPercentage]
      ,[DeliveryAddressDistrictName]
      ,[PriceVendorGroupCode]
      ,[PurchaseOrderHeaderCreationMethod]
      ,[DeliveryAddressCountyId]
      ,[DeliveryAddressZipCode]
      ,[IsConsolidatedInvoiceTarget]
      ,[ConfirmingPurchaseOrderCode]
      ,[LanguageId]
      ,[ReasonCode]
      ,[DeliveryAddressDunsNumber]
      ,[DeliveryTermsId]
      ,[BankDocumentType]
      ,[ExpectedStoreReceiptDate]
      ,[DeliveryAddressName]
      ,[InvoiceAddressCountryRegionId]
      ,[ReplenishmentServiceCategoryId]
      ,[PurchaseOrderPoolId]
      ,[DeliveryAddressStreetNumber]
      ,[RequestedShipDate]
      ,[ExpectedCrossDockingDate]
      ,[InvoiceAddressStreetNumber]
      ,[IsDeliveryAddressPrivate]
      ,[TaxExemptNumber]
      ,[FormattedInvoiceAddress]
      ,[BuyerGroupId]
      ,[DeliveryAddressCountryRegionISOCode]
      ,[CashDiscountCode]
      ,[PaymentScheduleName]
      ,[IntrastatTransactionCode]
      ,[URL]
      ,[CurrencyCode]
      ,[ConfirmingPurchaseOrderCodeLanguageId]
      ,[InvoiceType]
      ,[ArePricesIncludingSalesTax]
      ,[DeliveryAddressLocationId]
      ,[GSTSelfBilledInvoiceApprovalNumber]
      ,[IsDeliveredDirectly]
      ,[ConfirmedShipDate]
      ,[ShipCalendarId]
      ,[IntrastatStatisticsProcedureCode]
      ,[InvoiceVendorAccountNumber]
      ,[OverrideSalesTax]
      ,[DeliveryAddressStreet]
      ,[VendorOrderReference]
      ,[ReplenishmentWarehouseId]
      ,[FixedDueDate]
      ,[TransportationDocumentLineId]
      ,[SalesTaxGroupCode]
      ,[IsDeliveryAddressOrderSpecific]
      ,[VendorPostingProfileId]
      ,[VendorPaymentMethodSpecificationName]
      ,[InvoiceAddressCity]
      ,[ShippingCarrierServiceGroupId]
      ,[ContactPersonId]
      ,[DefaultReceivingWarehouseId]
      ,[EUSalesListCode]
      ,[ImportDeclarationNumber]
      ,[PurchaseOrderStatus]
      ,[PaymentTermsName]
      ,[DeliveryAddressLongitude]
      ,[DocumentApprovalStatus]
      ,[InvoiceAddressZipCode]
      ,[ShippingCarrierServiceId]
      ,[DefaultLedgerDimensionDisplayValue]
      ,[DeliveryAddressTimeZone]
      ,[AttentionInformation]
      ,[DeliveryAddressStateId]
      ,[DeliveryBuildingCompliment]
      ,[IntrastatTransportModeCode]
      ,[DeliveryAddressPostBox]
      ,[IsOneTimeVendor]
      ,[IntrastatPortId]
      ,[OrdererPersonnelNumber]
      ,[VendorPaymentMethodName]
      ,[InvoiceAddressState]
      ,[DefaultReceivingSiteId]
      ,[LineDiscountVendorGroupCode]
      ,[TransportationRoutePlanId]
      ,[ZakatContractNumber]
      ,[FormattedDeliveryAddress]
      ,[TotalDiscountVendorGroupCode]
      ,[TradeEndCustomerAccount]
      ,[FiscalDocumentOperationTypeId]
  FROM [MarinaDynamics365].[dbo].[PurchaseOrderHeadersV2_transit]

END
GO
/****** Object:  StoredProcedure [dbo].[InsertFromSelect]    Script Date: 30/07/2025 12:27:44 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO







CREATE PROCEDURE [dbo].[InsertFromSelect]
AS
BEGIN
    DECLARE @ref VARCHAR(255); -- Declare variable to hold the selected reference

    -- Cursor to iterate through the SELECT result
    DECLARE ref_cursor CURSOR FOR
    SELECT [ref] FROM [MarinaDynamics365].[dbo].[vw_Stock_Batch_correction_final_w_batch_lacking];

    OPEN ref_cursor;

    -- Fetch the first reference
    FETCH NEXT FROM ref_cursor INTO @ref;

    -- Loop through each reference and perform the INSERT
    WHILE @@FETCH_STATUS = 0
    BEGIN
        INSERT INTO [dbo].[Stock_Batch_correction_final_w_batch_lacking_corrected]
           ([Store Code]
           ,[Item number]
           ,[Item Name]
           ,[ref]
           ,[Site]
           ,[Warehouse]
           ,[Location]
           ,[Old Batch number]
           ,[Sales qty]
           ,[New_Batch]
           ,[Batch number]
           ,[Available physical]
           ,[New_Qty]
           ,[dIFF]
           ,[Expiry Date]
           ,[Unit]
           ,[all Batch On Hand]
           ,[REMARKS])
   
   SELECT [Store Code]
      ,l.[Item number]
      ,l.[Item Name]
      ,[ref]
      ,l.[Site]
      ,l.[Warehouse]
      ,l.[Location]
      ,[Old Batch number]
      ,[Sales qty]
      ,[New_Batch]
	  ,[Batch number]
	  ,[Available physical]
      ,[New_Qty]
      ,[dIFF]
      ,[Expiry Date]
      ,[Unit]
      ,[all Batch On Hand]
      ,[REMARKS]
	 
  FROM [MarinaDynamics365].[dbo].[vw_Stock_Batch_correction_final_w_batch_lacking] l,
  dbo.[ON hand Stock3] s
  where l.ref =s.[Site] +s.[Item number]
 and 
 ref=@ref
  and (SELECT 
          TOP 1  [Dummy]
  FROM [MarinaDynamics365].[dbo].[vw_ON_hand_Stock3_dummy]
 where  ref=@ref) <>0
 
 union
 SELECT top 1 [Store Code]
      ,l.[Item number]
      ,l.[Item Name]
      ,[ref]
      ,l.[Site]
      ,l.[Warehouse]
      ,l.[Location]
      ,[Old Batch number]
      ,[Sales qty]
      ,[New_Batch]
	  ,[Old Batch number] [Batch number]
	  ,[Sales qty] -(SELECT 
	  
	  sum(cast([Available physical] as decimal(8,2)))
    
  FROM [MarinaDynamics365].[dbo].[vw_Stock_Batch_correction_final_w_batch_lacking] l,
  dbo.[ON hand Stock3] s
  where l.ref =s.[Site] +s.[Item number]
and 
ref=@ref
  and cast([Available physical] as decimal(8,2))<>0
 ) [Available physical]
      ,[New_Qty]
      ,[dIFF]
      ,[Expiry Date]
      ,[Unit]
      ,'batch to add'[all Batch On Hand]
      ,'batch to add'[REMARKS]
  FROM [MarinaDynamics365].[dbo].[vw_Stock_Batch_correction_final_w_batch_lacking] l,
  dbo.[ON hand Stock3] s
  where l.ref =s.[Site] +s.[Item number] and 
 ref=@ref
  and cast([Available physical] as decimal(8,2))<>0



        -- Fetch the next reference
        FETCH NEXT FROM ref_cursor INTO @ref;
    END

    CLOSE ref_cursor;
    DEALLOCATE ref_cursor;
END
GO
/****** Object:  StoredProcedure [dbo].[InsertFromSelect_enough_Stock]    Script Date: 30/07/2025 12:27:44 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO





CREATE PROCEDURE [dbo].[InsertFromSelect_enough_Stock]
AS
BEGIN
 --delete from [dbo].[Stock_Batch_correction_final_w_batch_more_Stocks_corrected]
    DECLARE @ref VARCHAR(255); -- Declare variable to hold the selected reference

    -- Cursor to iterate through the SELECT result
    DECLARE ref_cursor CURSOR FOR
    SELECT [ref] FROM [MarinaDynamics365].[dbo].[vw_Stock_Batch_correction_final_w_batch_more_stocks];

    OPEN ref_cursor;

    -- Fetch the first reference
    FETCH NEXT FROM ref_cursor INTO @ref;

    -- Loop through each reference and perform the INSERT
    WHILE @@FETCH_STATUS = 0
    BEGIN
	   
        INSERT INTO [dbo].[Stock_Batch_correction_final_w_batch_more_Stocks_corrected]
           ([Store Code]
           ,[Item number]
           ,[Item Name]
           ,[ref]
           ,[Site]
           ,[Warehouse]
           ,[Location]
           ,[Old Batch number]
           ,[Sales qty]
           ,[New_Batch]
           ,[Batch number]
           ,[Available physical]
           ,[New_Qty]
           ,[dIFF]
           ,[Expiry Date]
           ,[Unit]
           ,[all Batch On Hand]
           ,[REMARKS])
   
   SELECT [Store Code]
      ,l.[Item number]
      ,l.[Item Name]
      ,[ref]
      ,l.[Site]
      ,l.[Warehouse]
      ,l.[Location]
      ,[Old Batch number]
      ,[Sales qty]
      ,[New_Batch]
	  ,[Batch number]
	  ,[Available physical]
      ,[New_Qty]
      ,[dIFF]
      ,[Expiry Date]
      ,[Unit]
      ,[all Batch On Hand]
      ,[REMARKS]
	 
  FROM [MarinaDynamics365].[dbo].[vw_Stock_Batch_correction_final_w_batch_more_stocks] l,
  dbo.[ON hand Stock3] s
  where l.ref =s.[Site] +s.[Item number]
 and 
 ref=@ref
  and cast([Available physical] as decimal(8,2))<>0
   and [Old Batch number]<>[Batch number]
 


        -- Fetch the next reference
        FETCH NEXT FROM ref_cursor INTO @ref;
    END

    CLOSE ref_cursor;
    DEALLOCATE ref_cursor;
END
GO
/****** Object:  StoredProcedure [dbo].[InsertFromSelect_orig]    Script Date: 30/07/2025 12:27:44 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO





CREATE PROCEDURE [dbo].[InsertFromSelect_orig]
AS
BEGIN
    DECLARE @ref VARCHAR(255); -- Declare variable to hold the selected reference

    -- Cursor to iterate through the SELECT result
    DECLARE ref_cursor CURSOR FOR
    SELECT [ref] FROM [MarinaDynamics365].[dbo].[vw_Stock_Batch_correction_final_w_batch_lacking];

    OPEN ref_cursor;

    -- Fetch the first reference
    FETCH NEXT FROM ref_cursor INTO @ref;

    -- Loop through each reference and perform the INSERT
    WHILE @@FETCH_STATUS = 0
    BEGIN
        INSERT INTO [dbo].[Stock_Batch_correction_final_w_batch_lacking_corrected]
           ([Store Code]
           ,[Item number]
           ,[Item Name]
           ,[ref]
           ,[Site]
           ,[Warehouse]
           ,[Location]
           ,[Old Batch number]
           ,[Sales qty]
           ,[New_Batch]
           ,[Batch number]
           ,[Available physical]
           ,[New_Qty]
           ,[dIFF]
           ,[Expiry Date]
           ,[Unit]
           ,[all Batch On Hand]
           ,[REMARKS])
   
   SELECT [Store Code]
      ,l.[Item number]
      ,l.[Item Name]
      ,[ref]
      ,l.[Site]
      ,l.[Warehouse]
      ,l.[Location]
      ,[Old Batch number]
      ,[Sales qty]
      ,[New_Batch]
	  ,[Batch number]
	  ,[Available physical]
      ,[New_Qty]
      ,[dIFF]
      ,[Expiry Date]
      ,[Unit]
      ,[all Batch On Hand]
      ,[REMARKS]
	 
  FROM [MarinaDynamics365].[dbo].[vw_Stock_Batch_correction_final_w_batch_lacking] l,
  dbo.[ON hand Stock3] s
  where l.ref =s.[Site] +s.[Item number]
 and 
 ref=@ref
  and cast([Available physical] as decimal(8,2))<>0
 
 union
 SELECT top 1 [Store Code]
      ,l.[Item number]
      ,l.[Item Name]
      ,[ref]
      ,l.[Site]
      ,l.[Warehouse]
      ,l.[Location]
      ,[Old Batch number]
      ,[Sales qty]
      ,[New_Batch]
	  ,[Old Batch number] [Batch number]
	  ,[Sales qty] -(SELECT 
	  
	  sum(cast([Available physical] as decimal(8,2)))
    
  FROM [MarinaDynamics365].[dbo].[vw_Stock_Batch_correction_final_w_batch_lacking] l,
  dbo.[ON hand Stock3] s
  where l.ref =s.[Site] +s.[Item number]
and 
ref=@ref
  and cast([Available physical] as decimal(8,2))<>0
 ) [Available physical]
      ,[New_Qty]
      ,[dIFF]
      ,[Expiry Date]
      ,[Unit]
      ,'batch to add'[all Batch On Hand]
      ,'batch to add'[REMARKS]
  FROM [MarinaDynamics365].[dbo].[vw_Stock_Batch_correction_final_w_batch_lacking] l,
  dbo.[ON hand Stock3] s
  where l.ref =s.[Site] +s.[Item number] and 
 ref=@ref
  and cast([Available physical] as decimal(8,2))<>0



        -- Fetch the next reference
        FETCH NEXT FROM ref_cursor INTO @ref;
    END

    CLOSE ref_cursor;
    DEALLOCATE ref_cursor;
END
GO
/****** Object:  StoredProcedure [dbo].[LPO_Dump_Import_from_D365_1Month]    Script Date: 30/07/2025 12:27:44 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO










CREATE PROCEDURE [dbo].[LPO_Dump_Import_from_D365_1Month]
AS
BEGIN






  delete  FROM [MarinaDynamics365].[dbo].ProductReceiptHeaders
  where [PurchaseOrderNumber] in ( SELECT [PurchaseOrderNumber] FROM [MarinaDynamics365].[dbo].[ProductReceiptHeaders_1M])

  INSERT INTO [dbo].[ProductReceiptHeaders]
         

     SELECT *

  FROM [MarinaDynamics365].[dbo].[ProductReceiptHeaders_1M]






   delete FROM [MarinaDynamics365].[dbo].ProductReceiptLines
  where [PurchaseOrderNumber]  in ( SELECT [PurchaseOrderNumber] FROM [MarinaDynamics365].[dbo].ProductReceiptLines_1M)



  
INSERT INTO [dbo].ProductReceiptLines ([dataAreaId]
      ,[RecordId]
      ,[ReceivedPurchaseQuantity]
      ,[ProductConfigurationId]
      ,[ReceivedInventoryQuantity]
      ,[PurchaseUnitSymbol]
      ,[LineNumber]
      ,[LineDescription]
      ,[ProductNumber]
      ,[ProductSizeId]
      ,[ItemNumber]
      ,[ProductVersionId]
      ,[ItemSerialNumber]
      ,[ReceivingSiteId]
      ,[ReceivedInventoryStatusId]
      ,[DeliveryAddressCountyId]
      ,[ProductReceiptNumber]
      ,[ProcurementProductCategoryHierarchyName]
      ,[ExpectedDeliveryDate]
      ,[RemainingInventoryQuantity]
      ,[DeliveryAddressCountryRegionId]
      ,[PurchaseOrderNumber]
      ,[ProductReceiptDate]
      ,[ExternalItemNumber]
      ,[OrderedPurchaseQuantity]
      ,[PurchaserPersonnelNumber]
      ,[ReceivingWarehouseId]
      ,[ProcurementProductCategoryName]
      ,[ItemBatchNumber]
      ,[RemainingPurchaseQuantity]
      ,[ProductColorId]
      ,[ProductReceiptHeaderRecordId]
      ,[DeliveryAddressStateId]
      ,[PurchaseOrderLineNumber]
      ,[ReceivingWarehouseLocationId]
      ,[ProductStyleId])
          

	SELECT  [dataAreaId]
      ,[RecordId]
      ,[ReceivedPurchaseQuantity]
      ,[ProductConfigurationId]
      ,[ReceivedInventoryQuantity]
      ,[PurchaseUnitSymbol]
      ,[LineNumber]
      ,[LineDescription]
      ,[ProductNumber]
      ,[ProductSizeId]
      ,[ItemNumber]
      ,[ProductVersionId]
      ,[ItemSerialNumber]
      ,[ReceivingSiteId]
      ,[ReceivedInventoryStatusId]
      ,[DeliveryAddressCountyId]
      ,[ProductReceiptNumber]
      ,[ProcurementProductCategoryHierarchyName]
      ,[ExpectedDeliveryDate]
      ,[RemainingInventoryQuantity]
      ,[DeliveryAddressCountryRegionId]
      ,[PurchaseOrderNumber]
      ,[ProductReceiptDate]
      ,[ExternalItemNumber]
      ,[OrderedPurchaseQuantity]
      ,[PurchaserPersonnelNumber]
      ,[ReceivingWarehouseId]
      ,[ProcurementProductCategoryName]
      ,[ItemBatchNumber]
      ,[RemainingPurchaseQuantity]
      ,[ProductColorId]
      ,[ProductReceiptHeaderRecordId]
      ,[DeliveryAddressStateId]
      ,[PurchaseOrderLineNumber]
      ,[ReceivingWarehouseLocationId]
      ,[ProductStyleId]
  FROM [MarinaDynamics365].[dbo].ProductReceiptLines_1M



  --===========================================


  
  delete FROM [MarinaDynamics365].[dbo].PurchaseOrderHeadersV2
  where [PurchaseOrderNumber] in ( SELECT [PurchaseOrderNumber] FROM [MarinaDynamics365].[dbo].PurchaseOrderHeadersV2_1M)

  INSERT INTO [dbo].PurchaseOrderHeadersV2
         

     SELECT *

  FROM [MarinaDynamics365].[dbo].PurchaseOrderHeadersV2_1M



    delete FROM [MarinaDynamics365].[dbo].PurchaseOrderLinesV2
  where [PurchaseOrderNumber] in ( SELECT [PurchaseOrderNumber] FROM [MarinaDynamics365].[dbo].PurchaseOrderLinesV2_1M)

  INSERT INTO [dbo].PurchaseOrderLinesV2
         

     SELECT *

  FROM [MarinaDynamics365].[dbo].PurchaseOrderLinesV2_1M


	 
	 
END
GO
/****** Object:  StoredProcedure [dbo].[MinMax_ExecuteDynamicSQLAndLog]    Script Date: 30/07/2025 12:27:44 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO

CREATE PROCEDURE [dbo].[MinMax_ExecuteDynamicSQLAndLog]
    (@SqlDesc NVARCHAR(MAX),@SqlQuery NVARCHAR(MAX))
AS
BEGIN
    DECLARE @ResultMessage NVARCHAR(MAX);
    DECLARE @RowsAffected INT;
	DECLARE @StartTime DATETIME;
    DECLARE @EndTime DATETIME;
    DECLARE @DurationMilliseconds INT;

	SET @StartTime = GETDATE();

    BEGIN TRY
        EXEC sp_executesql @SqlQuery;

		

        SET @RowsAffected = @@ROWCOUNT;
        SET @ResultMessage = 'Success! Query executed successfully. Rows affected: ' + CAST(@RowsAffected AS NVARCHAR(10));
		SET @EndTime = GETDATE();
        SET @DurationMilliseconds = DATEDIFF(SECOND, @StartTime, @EndTime);
    END TRY
    BEGIN CATCH

        SET @RowsAffected = 0;
        SET @ResultMessage = 'Error: ' + ERROR_MESSAGE();
		SET @EndTime = GETDATE();
        SET @DurationMilliseconds = DATEDIFF(SECOND, @StartTime, @EndTime);
    END CATCH

    INSERT INTO dbo.[MinMax_QueryExecutionLog] (QueryText, ExecutionDateTime, RowsAffected, ResultMessage,Duration)
    VALUES (@SqlDesc, GETDATE(), @RowsAffected, @ResultMessage,dbo.SecTimeDay(@DurationMilliseconds) );
END;

GO
/****** Object:  StoredProcedure [dbo].[Proc_email_Marketplace_Matrix]    Script Date: 30/07/2025 12:27:44 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO








create procedure [dbo].[Proc_email_Marketplace_Matrix]

as
SET 
  ANSI_NULLS, 
  QUOTED_IDENTIFIER, 
  CONCAT_NULL_YIELDS_NULL, 
  ANSI_WARNINGS, 
  ANSI_PADDING 
ON;


DECLARE @xml NVARCHAR(MAX)
DECLARE @body NVARCHAR(MAX)
DECLARE @subj_c NVARCHAR(MAX)
DECLARE @CC NVARCHAR(MAX)
    

SET @xml = CAST((SELECT  [storecode]  AS 'td',''
      ,[Branch] AS 'td',''
      ,[Talabat_Active] AS 'td',''
      ,[Talabat_InActive] AS 'td',''
      ,[Instashop_Active] AS 'td',''
      ,[Instashop_InActive] AS 'td',''
      ,[NowNow_Active] AS 'td',''
      ,[NowNow_InActive] AS 'td',''
      ,[Careem_Active] AS 'td',''
      ,[Careem_InActive] AS 'td',''
      ,[Deliveroo_Active] AS 'td',''
      ,[Deliveroo_InActive] AS 'td',''
      ,[Swan_Active] AS 'td',''
      ,[SwanIn_Active] AS 'td',''
  FROM [MarinaDashboard].[dbo].[MarketPlace_Item_Availability_Matrix]

FOR XML PATH('tr'), ELEMENTS ) AS NVARCHAR(MAX))

set @subj_c ='Marketplace Stock Availability Matrix ' 




SET @body ='<html><style>
.zui-table {
    border: solid 1px #000000;
    border-collapse: collapse;
    border-spacing: 0;
    font: normal 12px Calibri, sans-serif;
}
.zui-table thead th {
    background-color: #ffffff;
    border: solid 1px #000000;
    color: #000000;
    padding: 3px;
    text-align: left;
    text-shadow: 1px 1px 1px #fff;
}
.zui-table tbody td {
    border: solid 1px #000000;
    color: #333;
    padding: 3px;
    text-shadow: 1px 1px 1px #fff;
	text-align: center;
}
</style><body><font face="Calibri">Dear Team, <br><br>FYI.<br><br>
Please find below Marketplace Stock Availability Matrix:<BR><br>
<table  class="zui-table">
<thead>
<tr>
	<th> StoreCode</th>
     <th> Branch </th>
     <th> Talabat 1''s </th>
     <th> Talabat 0''s </th>
     <th> Insta 1''s</th>
	 <th> Insta 0''s </th>
     <th> NowNow 1''s </th>
     <th> NowNow 0''s </th>
     <th> Careem 1''s </th>
     <th> Careem 0''s</th>
     <th> Deliveroo 1''s </th>
     <th> Deliveroo 0''s </th>
	 <th> Swan 1''s </th>
	 <th> Swan 0''s </th>
</tr>
</thead> <tbody>' 
 
SET @body = @body + @xml +'</tbody></table><br>
<br><br><br>
NOTE: <I>This is email is autogenerated. Do Not Reply.</I>
<br><br><br><br>
Thank you! </font>
</body></html>'


EXEC msdb.dbo.sp_send_dbmail
@profile_name = 'NoReply', -- replace with your SQL Database Mail Profile 
@body = @body,
@body_format ='HTML',
@recipients =  'Michael@800pharmacy.ae;it@marinapharmacy.com' , -- replace with your email address
@subject = @subj_c ;
    
    


  












GO
/****** Object:  StoredProcedure [dbo].[Re_Order_Allocate_order]    Script Date: 30/07/2025 12:27:44 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO






















CREATE PROCEDURE [dbo].[Re_Order_Allocate_order]
AS
BEGIN
    DECLARE @ItemNumber VARCHAR(255),
	@turn int; -- Declare variable to hold the selected reference

	delete from [dbo].[REORDER_branch_order_pass_1]
    -- Cursor to iterate through the SELECT result
    DECLARE ref_cursor CURSOR FOR
    
	SELECT [ItemNumber] FROM [MarinaDynamics365].[dbo].FEB2024_MinMax_RE_Order_Branch_Final
	where Store_Stock<>0 
          group by [ItemNumber] 
   
    OPEN ref_cursor;

    -- Fetch the first reference
    FETCH NEXT FROM ref_cursor INTO @ItemNumber;

    -- Loop through each reference and perform the INSERT
    WHILE @@FETCH_STATUS = 0
    BEGIN
     
				DECLARE ref_cursor2 CURSOR FOR
    
					SELECT cast(turn as int) FROM [MarinaDynamics365].[dbo].FEB2024_MinMax_RE_Order_Branch_Final
				   where itemnumber = @ItemNumber   and [order]<>0
				   order by cast(turn as int) asc
   
				OPEN ref_cursor2;

				-- Fetch the first reference
				FETCH NEXT FROM ref_cursor2 INTO @turn;

				-- Loop through each reference and perform the INSERT
				WHILE @@FETCH_STATUS = 0
				BEGIN
     
							INSERT INTO [dbo].[REORDER_branch_order_pass_1]
									   ([ItemNumber]
									   ,[ProductName]
									   ,[STORECODE]
									   ,[LocationID]
									   ,[ShortName]
									   ,[Min]
									   ,[Max]
									   ,[Order]
									   ,[Turn]
									   ,[Store_Stock]
									   ,[taken]
									   ,[Running_Stock]
									  ,Category
									  ,Stock
									,  Unposted_Qty
									,Cost
									
									  ,[Stock_after_Unposted]
									   )


							SELECT [ItemNumber]
								  ,[ProductName]
								  ,[STORECODE]
								  ,[LocationID]
								  ,[ShortName]
								  ,[Min]
								  ,[Max]
								  ,[Order]
								  , [Turn]
								  ,isnull((SELECT 
								    [Stock]
									FROM [MarinaDynamics365].[dbo].[Drug_Batch_Stock_ordered_SUM_STORE] s
									where s.[ItemNumber]=o.[ItemNumber] ),0) Store_Stock
															 
								  ,case when isnull((SELECT 
									[Stock]
									 FROM [MarinaDynamics365].[dbo].[Drug_Batch_Stock_ordered_SUM_STORE] s
									where s.[ItemNumber]=o.[ItemNumber] ),0) -

							      isnull( ( SELECT  
									 sum(taken)
    
								  FROM [MarinaDynamics365].[dbo].[REORDER_branch_order_pass_1]
								  where itemnumber= @ItemNumber  ),0)
									
									>= [Order] then  [Order]
									
									else 
									isnull((SELECT 
									sum([Stock])
									 FROM [MarinaDynamics365].[dbo].[Drug_Batch_Stock_ordered_SUM_STORE] s
									where s.[ItemNumber]=o.[ItemNumber] ),0)  -

									   isnull(( SELECT  
									  sum(taken)
    
								  FROM [MarinaDynamics365].[dbo].[REORDER_branch_order_pass_1]
								  where itemnumber= @ItemNumber  ),0)
									end  taken


									 ,isnull((SELECT 
									sum([Stock])
									 FROM [MarinaDynamics365].[dbo].[Drug_Batch_Stock_ordered_SUM_STORE] s
									where s.[ItemNumber]=o.[ItemNumber] ),0)  -

									   isnull(( SELECT  
									  sum(taken)
    
								  FROM [MarinaDynamics365].[dbo].[REORDER_branch_order_pass_1]
								  where itemnumber= @ItemNumber  ),0)
								  ,Category
								  ,Stock
								  ,[Qty_Unposted]
								  ,Cost
								  ,[Stock_after_Unposted]
							  FROM [MarinaDynamics365].[dbo].FEB2024_MinMax_RE_Order_Branch_Final o
							  where cast(turn as int) = @turn and itemnumber = @ItemNumber
  



					-- Fetch the next reference
					FETCH NEXT FROM ref_cursor2 INTO @turn;
				END

				CLOSE ref_cursor2;
				DEALLOCATE ref_cursor2;
	





        -- Fetch the next reference
        FETCH NEXT FROM ref_cursor INTO @ItemNumber;
    END

	



    CLOSE ref_cursor;
    DEALLOCATE ref_cursor;
END
GO
/****** Object:  StoredProcedure [dbo].[Re_Order_Allocate_order_800Store]    Script Date: 30/07/2025 12:27:44 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO



















CREATE PROCEDURE [dbo].[Re_Order_Allocate_order_800Store]
AS
BEGIN
    DECLARE @ItemNumber VARCHAR(255),
	@turn int; -- Declare variable to hold the selected reference

	delete from [dbo].[REORDER_branch_order_pass_800_1]
    -- Cursor to iterate through the SELECT result
    DECLARE ref_cursor CURSOR FOR
    
	SELECT [ItemNumber] FROM [MarinaDynamics365].[dbo].FEB2024_MinMax_RE_Order_Branch_Final_800
	where Store_Stock<>0 
          group by [ItemNumber] 
   
    OPEN ref_cursor;

    -- Fetch the first reference
    FETCH NEXT FROM ref_cursor INTO @ItemNumber;

    -- Loop through each reference and perform the INSERT
    WHILE @@FETCH_STATUS = 0
    BEGIN
     
				DECLARE ref_cursor2 CURSOR FOR
    
					SELECT cast(turn as int) FROM [MarinaDynamics365].[dbo].FEB2024_MinMax_RE_Order_Branch_Final_800
				   where itemnumber = @ItemNumber  and [order]<>0
				   order by cast(turn as int) asc
   
				OPEN ref_cursor2;

				-- Fetch the first reference
				FETCH NEXT FROM ref_cursor2 INTO @turn;

				-- Loop through each reference and perform the INSERT
				WHILE @@FETCH_STATUS = 0
				BEGIN
     
							INSERT INTO [dbo].[REORDER_branch_order_pass_800_1]
									   ([ItemNumber]
									   ,[ProductName]
									   ,[STORECODE]
									   ,[LocationID]
									   ,[ShortName]
									   ,[Min]
									   ,[Max]
									   ,[Order]
									   ,[Turn]
									   ,[Store_Stock]
									   ,[taken]
									   ,[Running_Stock]
									  ,Category
									  ,Stock
									  ,Cost
									  ,Qty_Unposted
									   ,[Stock_after_Unposted]
									   
									   )


							SELECT [ItemNumber]
								  ,[ProductName]
								  ,[STORECODE]
								  ,[LocationID]
								  ,[ShortName]
								  ,[Min]
								  ,[Max]
								  ,[Order]
								  , [Turn]
								  ,isnull((SELECT 
								    [Stock]
									FROM [MarinaDynamics365].[dbo].Drug_Batch_Stock_ordered_SUM_800STORE s
									where s.[ItemNumber]=o.[ItemNumber] ),0) Store_Stock
															 
								  ,case when isnull((SELECT 
									[Stock]
									 FROM [MarinaDynamics365].[dbo].Drug_Batch_Stock_ordered_SUM_800STORE s
									where s.[ItemNumber]=o.[ItemNumber] ),0) -

							      isnull( ( SELECT  
									 sum(taken)
    
								  FROM [MarinaDynamics365].[dbo].[REORDER_branch_order_pass_800_1]
								  where itemnumber= @ItemNumber  ),0)
									
									>= [Order] then  [Order]
									
									else 
									isnull((SELECT 
									sum([Stock])
									 FROM [MarinaDynamics365].[dbo].Drug_Batch_Stock_ordered_SUM_800STORE s
									where s.[ItemNumber]=o.[ItemNumber] ),0)  -

									   isnull(( SELECT  
									  sum(taken)
    
								  FROM [MarinaDynamics365].[dbo].[REORDER_branch_order_pass_800_1]
								  where itemnumber= @ItemNumber  ),0)
									end  taken


									 ,isnull((SELECT 
									sum([Stock])
									 FROM [MarinaDynamics365].[dbo].Drug_Batch_Stock_ordered_SUM_800STORE s
									where s.[ItemNumber]=o.[ItemNumber] ),0)  -

									   isnull(( SELECT  
									  sum(taken)
    
								  FROM [MarinaDynamics365].[dbo].[REORDER_branch_order_pass_800_1]
								  where itemnumber= @ItemNumber  ),0)
								  ,Category
								   ,Stock
								    ,Cost
									  ,Qty_Unposted
									   ,[Stock_after_Unposted]
							  FROM [MarinaDynamics365].[dbo].FEB2024_MinMax_RE_Order_Branch_Final_800 o
							  where turn = @turn and itemnumber = @ItemNumber
  



					-- Fetch the next reference
					FETCH NEXT FROM ref_cursor2 INTO @turn;
				END

				CLOSE ref_cursor2;
				DEALLOCATE ref_cursor2;
	





        -- Fetch the next reference
        FETCH NEXT FROM ref_cursor INTO @ItemNumber;
    END


	

    CLOSE ref_cursor;
    DEALLOCATE ref_cursor;
END
GO
/****** Object:  StoredProcedure [dbo].[Re_Order_Allocate_order_800Store_br_zero]    Script Date: 30/07/2025 12:27:44 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO





















CREATE PROCEDURE [dbo].[Re_Order_Allocate_order_800Store_br_zero]
AS
BEGIN
    DECLARE @ItemNumber VARCHAR(255),
	@turn int; -- Declare variable to hold the selected reference

	delete from [dbo].[REORDER_branch_order_pass_800_1_br_zero]
    -- Cursor to iterate through the SELECT result
    DECLARE ref_cursor CURSOR FOR
    
	SELECT [ItemNumber] FROM [MarinaDynamics365].[dbo].FEB2024_MinMax_RE_Order_Branch_Final_800
	where Store_Stock<>0 
          group by [ItemNumber] 
   
    OPEN ref_cursor;

    -- Fetch the first reference
    FETCH NEXT FROM ref_cursor INTO @ItemNumber;

    -- Loop through each reference and perform the INSERT
    WHILE @@FETCH_STATUS = 0
    BEGIN
     
				DECLARE ref_cursor2 CURSOR FOR
    
					SELECT cast(turn as int) FROM [MarinaDynamics365].[dbo].FEB2024_MinMax_RE_Order_Branch_Final_800
				   where itemnumber = @ItemNumber  and [order]<>0 and stock=0 and CONS<>0
				   order by cast(turn as int) asc
   
				OPEN ref_cursor2;

				-- Fetch the first reference
				FETCH NEXT FROM ref_cursor2 INTO @turn;

				-- Loop through each reference and perform the INSERT
				WHILE @@FETCH_STATUS = 0
				BEGIN
     
							INSERT INTO [dbo].[REORDER_branch_order_pass_800_1_br_zero]
									   ([ItemNumber]
									   ,[ProductName]
									   ,[STORECODE]
									   ,[LocationID]
									   ,[ShortName]
									   ,[Min]
									   ,[Max]
									   ,[Order]
									   ,[Turn]
									   ,[Store_Stock]
									   ,[taken]
									   ,[Running_Stock]
									  ,Category
									  ,Stock
									  ,Cost
									  ,Qty_Unposted
									   ,[Stock_after_Unposted]
									   
									   )


							SELECT [ItemNumber]
								  ,[ProductName]
								  ,[STORECODE]
								  ,[LocationID]
								  ,[ShortName]
								  ,[Min]
								  ,[Max]
								  ,[Order]
								  , [Turn]
								  ,isnull((SELECT 
								    [Stock]
									FROM [MarinaDynamics365].[dbo].Drug_Batch_Stock_ordered_SUM_800STORE s
									where s.[ItemNumber]=o.[ItemNumber] ),0) Store_Stock
															 
								  ,case when isnull((SELECT 
									[Stock]
									 FROM [MarinaDynamics365].[dbo].Drug_Batch_Stock_ordered_SUM_800STORE s
									where s.[ItemNumber]=o.[ItemNumber] ),0) -

							      isnull( ( SELECT  
									 sum(taken)
    
								  FROM [MarinaDynamics365].[dbo].[REORDER_branch_order_pass_800_1_br_zero]
								  where itemnumber= @ItemNumber  ),0)
									
									>= [Order] then  [Order]
									
									else 
									isnull((SELECT 
									sum([Stock])
									 FROM [MarinaDynamics365].[dbo].Drug_Batch_Stock_ordered_SUM_800STORE s
									where s.[ItemNumber]=o.[ItemNumber] ),0)  -

									   isnull(( SELECT  
									  sum(taken)
    
								  FROM [MarinaDynamics365].[dbo].[REORDER_branch_order_pass_800_1_br_zero]
								  where itemnumber= @ItemNumber  ),0)
									end  taken


									 ,isnull((SELECT 
									sum([Stock])
									 FROM [MarinaDynamics365].[dbo].Drug_Batch_Stock_ordered_SUM_800STORE s
									where s.[ItemNumber]=o.[ItemNumber] ),0)  -

									   isnull(( SELECT  
									  sum(taken)
    
								  FROM [MarinaDynamics365].[dbo].[REORDER_branch_order_pass_800_1_br_zero]
								  where itemnumber= @ItemNumber  ),0)
								  ,Category
								   ,Stock
								    ,Cost
									  ,Qty_Unposted
									   ,[Stock_after_Unposted]
							  FROM [MarinaDynamics365].[dbo].FEB2024_MinMax_RE_Order_Branch_Final_800 o
							  where turn = @turn and itemnumber = @ItemNumber
									--	AND stock=0 and CONS<>0



					-- Fetch the next reference
					FETCH NEXT FROM ref_cursor2 INTO @turn;
				END

				CLOSE ref_cursor2;
				DEALLOCATE ref_cursor2;
	





        -- Fetch the next reference
        FETCH NEXT FROM ref_cursor INTO @ItemNumber;
    END


	

    CLOSE ref_cursor;
    DEALLOCATE ref_cursor;
END
GO
/****** Object:  StoredProcedure [dbo].[Re_Order_Allocate_order_br_zero]    Script Date: 30/07/2025 12:27:44 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO
























CREATE PROCEDURE [dbo].[Re_Order_Allocate_order_br_zero]
AS
BEGIN
    DECLARE @ItemNumber VARCHAR(255),
	@turn int; -- Declare variable to hold the selected reference

	delete from [dbo].[REORDER_branch_order_pass_1_br_zero]
    -- Cursor to iterate through the SELECT result
    DECLARE ref_cursor CURSOR FOR
    
	SELECT [ItemNumber] FROM [MarinaDynamics365].[dbo].FEB2024_MinMax_RE_Order_Branch_Final
	where Store_Stock<>0 
          group by [ItemNumber] 
   
    OPEN ref_cursor;

    -- Fetch the first reference
    FETCH NEXT FROM ref_cursor INTO @ItemNumber;

    -- Loop through each reference and perform the INSERT
    WHILE @@FETCH_STATUS = 0
    BEGIN
     
				DECLARE ref_cursor2 CURSOR FOR
    
					SELECT cast(turn as int) FROM [MarinaDynamics365].[dbo].FEB2024_MinMax_RE_Order_Branch_Final
				   where itemnumber = @ItemNumber   and [order]<>0 and stock=0 and CONS<>0
				   order by cast(turn as int) asc
   
				OPEN ref_cursor2;

				-- Fetch the first reference
				FETCH NEXT FROM ref_cursor2 INTO @turn;

				-- Loop through each reference and perform the INSERT
				WHILE @@FETCH_STATUS = 0
				BEGIN
     
							INSERT INTO [dbo].[REORDER_branch_order_pass_1_br_zero]
									   ([ItemNumber]
									   ,[ProductName]
									   ,[STORECODE]
									   ,[LocationID]
									   ,[ShortName]
									   ,[Min]
									   ,[Max]
									   ,[Order]
									   ,[Turn]
									   ,[Store_Stock]
									   ,[taken]
									   ,[Running_Stock]
									  ,Category
									  ,Stock
									,  Unposted_Qty
									,Cost
									
									  ,[Stock_after_Unposted]
									   )


							SELECT [ItemNumber]
								  ,[ProductName]
								  ,[STORECODE]
								  ,[LocationID]
								  ,[ShortName]
								  ,[Min]
								  ,[Max]
								  ,[Order]
								  , [Turn]
								  ,isnull((SELECT 
								    [Stock]
									FROM [MarinaDynamics365].[dbo].[Drug_Batch_Stock_ordered_SUM_STORE] s
									where s.[ItemNumber]=o.[ItemNumber] ),0) Store_Stock
															 
								  ,case when isnull((SELECT 
									[Stock]
									 FROM [MarinaDynamics365].[dbo].[Drug_Batch_Stock_ordered_SUM_STORE] s
									where s.[ItemNumber]=o.[ItemNumber] ),0) -

							      isnull( ( SELECT  
									 sum(taken)
    
								  FROM [MarinaDynamics365].[dbo].[REORDER_branch_order_pass_1_br_zero]
								  where itemnumber= @ItemNumber  ),0)
									
									>= [Order] then  [Order]
									
									else 
									isnull((SELECT 
									sum([Stock])
									 FROM [MarinaDynamics365].[dbo].[Drug_Batch_Stock_ordered_SUM_STORE] s
									where s.[ItemNumber]=o.[ItemNumber] ),0)  -

									   isnull(( SELECT  
									  sum(taken)
    
								  FROM [MarinaDynamics365].[dbo].[REORDER_branch_order_pass_1_br_zero]
								  where itemnumber= @ItemNumber  ),0)
									end  taken


									 ,isnull((SELECT 
									sum([Stock])
									 FROM [MarinaDynamics365].[dbo].[Drug_Batch_Stock_ordered_SUM_STORE] s
									where s.[ItemNumber]=o.[ItemNumber] ),0)  -

									   isnull(( SELECT  
									  sum(taken)
    
								  FROM [MarinaDynamics365].[dbo].[REORDER_branch_order_pass_1_br_zero]
								  where itemnumber= @ItemNumber  ),0)
								  ,Category
								  ,Stock
								  ,[Qty_Unposted]
								  ,Cost
								  ,[Stock_after_Unposted]
							  FROM [MarinaDynamics365].[dbo].FEB2024_MinMax_RE_Order_Branch_Final o
							  where turn = @turn and itemnumber = @ItemNumber
							
  



					-- Fetch the next reference
					FETCH NEXT FROM ref_cursor2 INTO @turn;
				END

				CLOSE ref_cursor2;
				DEALLOCATE ref_cursor2;
	





        -- Fetch the next reference
        FETCH NEXT FROM ref_cursor INTO @ItemNumber;
    END

	



    CLOSE ref_cursor;
    DEALLOCATE ref_cursor;
END
GO
/****** Object:  StoredProcedure [dbo].[Re_Order_Allocate_order_Max]    Script Date: 30/07/2025 12:27:44 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO























CREATE PROCEDURE [dbo].[Re_Order_Allocate_order_Max]
AS
BEGIN
    DECLARE @ItemNumber VARCHAR(255),
	@turn int; -- Declare variable to hold the selected reference

	delete from [dbo].[REORDER_branch_order_pass_1_max]
    -- Cursor to iterate through the SELECT result
    DECLARE ref_cursor CURSOR FOR
    
	SELECT [ItemNumber] FROM [MarinaDynamics365].[dbo].FEB2024_MinMax_RE_Order_Branch_Final_max
	where Store_Stock<>0 
          group by [ItemNumber] 
   
    OPEN ref_cursor;

    -- Fetch the first reference
    FETCH NEXT FROM ref_cursor INTO @ItemNumber;

    -- Loop through each reference and perform the INSERT
    WHILE @@FETCH_STATUS = 0
    BEGIN
     
				DECLARE ref_cursor2 CURSOR FOR
    
					SELECT cast(turn as int) FROM [MarinaDynamics365].[dbo].FEB2024_MinMax_RE_Order_Branch_Final_max
				   where itemnumber = @ItemNumber   and [order]<>0
				   order by cast(turn as int) asc
   
				OPEN ref_cursor2;

				-- Fetch the first reference
				FETCH NEXT FROM ref_cursor2 INTO @turn;

				-- Loop through each reference and perform the INSERT
				WHILE @@FETCH_STATUS = 0
				BEGIN
     
							INSERT INTO [dbo].[REORDER_branch_order_pass_1_max]
									   ([ItemNumber]
									   ,[ProductName]
									   ,[STORECODE]
									   ,[LocationID]
									   ,[ShortName]
									   ,[Min]
									   ,[Max]
									   ,[Order]
									   ,[Turn]
									   ,[Store_Stock]
									   ,[taken]
									   ,[Running_Stock]
									  ,Category
									  ,Stock
									,  Unposted_Qty
									,Cost
									
									  ,[Stock_after_Unposted]
									   )


							SELECT [ItemNumber]
								  ,[ProductName]
								  ,[STORECODE]
								  ,[LocationID]
								  ,[ShortName]
								  ,[Min]
								  ,[Max]
								  ,[Order]
								  , [Turn]
								  ,isnull((SELECT 
								    [Stock]
									FROM [MarinaDynamics365].[dbo].[Drug_Batch_Stock_ordered_SUM_STORE] s
									where s.[ItemNumber]=o.[ItemNumber] ),0) Store_Stock
															 
								  ,case when isnull((SELECT 
									[Stock]
									 FROM [MarinaDynamics365].[dbo].[Drug_Batch_Stock_ordered_SUM_STORE] s
									where s.[ItemNumber]=o.[ItemNumber] ),0) -

							      isnull( ( SELECT  
									 sum(taken)
    
								  FROM [MarinaDynamics365].[dbo].[REORDER_branch_order_pass_1_max]
								  where itemnumber= @ItemNumber  ),0)
									
									>= [Order] then  [Order]
									
									else 
									isnull((SELECT 
									sum([Stock])
									 FROM [MarinaDynamics365].[dbo].[Drug_Batch_Stock_ordered_SUM_STORE] s
									where s.[ItemNumber]=o.[ItemNumber] ),0)  -

									   isnull(( SELECT  
									  sum(taken)
    
								  FROM [MarinaDynamics365].[dbo].[REORDER_branch_order_pass_1_max]
								  where itemnumber= @ItemNumber  ),0)
									end  taken


									 ,isnull((SELECT 
									sum([Stock])
									 FROM [MarinaDynamics365].[dbo].[Drug_Batch_Stock_ordered_SUM_STORE] s
									where s.[ItemNumber]=o.[ItemNumber] ),0)  -

									   isnull(( SELECT  
									  sum(taken)
    
								  FROM [MarinaDynamics365].[dbo].[REORDER_branch_order_pass_1_max]
								  where itemnumber= @ItemNumber  ),0)
								  ,Category
								  ,Stock
								  ,[Qty_Unposted]
								  ,Cost
								  ,[Stock_after_Unposted]
							  FROM [MarinaDynamics365].[dbo].FEB2024_MinMax_RE_Order_Branch_Final_max o
							  where cast(turn as int) = @turn and itemnumber = @ItemNumber
  



					-- Fetch the next reference
					FETCH NEXT FROM ref_cursor2 INTO @turn;
				END

				CLOSE ref_cursor2;
				DEALLOCATE ref_cursor2;
	





        -- Fetch the next reference
        FETCH NEXT FROM ref_cursor INTO @ItemNumber;
    END

	



    CLOSE ref_cursor;
    DEALLOCATE ref_cursor;
END
GO
/****** Object:  StoredProcedure [dbo].[ReleasedProductCreations_Import_from_D365]    Script Date: 30/07/2025 12:27:44 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO











CREATE PROCEDURE [dbo].[ReleasedProductCreations_Import_from_D365]
AS
BEGIN
   


delete from [MarinaDynamics365].[dbo].[Mx_Product_Master_new]
INSERT INTO [MarinaDynamics365].[dbo].[Mx_Product_Master_new]
           ([ItemNumber]
           ,[ProductName]
           ,[PurchaseUnitSymbol]
           ,[ProductGroupId]
           ,[RetailProductCategoryname]
           ,[BOMUnitSymbol]
           ,[SearchName]
           ,[SalesSalesTaxItemGroupCode]
           ,[SalesUnitSymbol]
           ,[ProductDescription]
           ,[PurchaseSalesTaxItemGroupCode]
           ,[Drug_id]
		   ,Factor
		   ,Comments
		 )
 

SELECT [ItemNumber]
	   ,[ProductName]
      ,'' [PurchaseUnitSymbol]
      ,[ProductGroupId]
      ,[RetailProductCategoryname]
      ,[BOMUnitSymbol]
      ,'' [SearchName]
      ,[SalesSalesTaxItemGroupCode]
      ,''[SalesUnitSymbol]
      ,''[ProductDescription]
      ,[PurchaseSalesTaxItemGroupCode]
      , Drug_id
	  , Factor
	 
	 ,Comments
   
  FROM [MarinaDynamics365].[dbo].vw_ReleasedProductCreationsV2_auto 

 

 update  [MarinaDynamics365].[dbo].[Mx_Product_Master_new]
 set  [Order_Group] = (select [Order_Group]   FROM [MarinaDynamics365].[dbo].[Mx_Product_Order_Group_ALL_WH] op
 where op.drug_id=[MarinaDynamics365].[dbo].[Mx_Product_Master_new].Drug_id)

 update 
dbo.Mx_Product_Master_new
set Order_Group ='Warehouse (Expensive)'
WHERE        (ItemNumber IN ('114758', '114445', '114630', '114386', '114569', '114570', '114557', '114558', '114188', '114508', '106440', '112065','114821','114822','114823','114824','114825','114820','114486','102847','114819','114152','107350','111692','107645','115269'
,'115079'
,'104584'
,'110223'
,'111000'
,'115266'
,'115118'
,'115294'
,'115190'
,'115184'
,'115080'
))


update 
dbo.Mx_Product_Master_new
set Order_Group ='Warehouse (Controlled)'
WHERE        (ItemNumber IN ('111425', '111426', '112264', '111644', '111134', '109821', '109822', '107643', '102634', '102601', '107719', '109005', '109006', '109024', '106557', '111470', '100812', '100220', '102074', '100732', '102895', 
                         '108434', '108243', '108242', '111565', '111564', '108914', '110694', '101711', '108245', '110485', '100702', '100703', '111567','103326','107645','111692'))

 update  [MarinaDynamics365].[dbo].[Mx_Product_Master_new]
 set  [Order_Group] = 'Not Classified'
 where isnull([Order_Group],'x')='x'
 and ItemNumber < '114383'

  update  [MarinaDynamics365].[dbo].[Mx_Product_Master_new]
 set  [Order_Group] = 'Warehouse'
 where isnull([Order_Group],'x')='x'
 and ItemNumber > '114383'


delete FROM [MarinaDynamics365].[dbo].[Mx_Product_Master_new]
WHERE LEFT(ItemNumber,1)<>'1'

 delete [MarinaDynamics365].[dbo].[Mx_Product_Master]
  INSERT INTO [dbo].[Mx_Product_Master]
           ([Item number]
           ,[Product name]
           ,[Old_Drug_ID_Prefix]
           ,[DrugName]
           ,[Drug_ID]
           ,[ITEMGROUP]
           ,[RECID]
           ,[PRODUCT]
           ,[PRODUCTNAME]
           ,[Brand_name]
           ,[Sub_Category])
 
 SELECT [ItemNumber]
    ,[ProductName]
  ,''
  ,''
   , Drug_id
   ,[ProductGroupId]
     ,''
	  ,''
	  ,[ProductName]
	,''
	 ,[RetailProductCategoryname]
    
  FROM [MarinaDynamics365].[dbo].vw_ReleasedProductCreationsV2_auto 




 DROP TABLE [MarinaDynamics365].DBO.Mx_Product_Master_new_w_location

SELECT * 
INTO [MarinaDynamics365].DBO.Mx_Product_Master_new_w_location
FROM [MarinaDynamics365].DBO.vw_Mx_Product_Master_new_w_location





--delete from [dbo].[LPO_Master]
--where sessionid='D365'


delete from [MarinaDashboard].[dbo].[Mx_Product_Master_new]
INSERT INTO [MarinaDashboard].[dbo].[Mx_Product_Master_new]
           ([ItemNumber]
           ,[ProductName]
           ,[PurchaseUnitSymbol]
           ,[ProductGroupId]
           ,[RetailProductCategoryname]
           ,[BOMUnitSymbol]
           ,[SearchName]
           ,[SalesSalesTaxItemGroupCode]
           ,[SalesUnitSymbol]
           ,[ProductDescription]
           ,[PurchaseSalesTaxItemGroupCode]
           ,[Drug_id]
		   ,Factor
		   ,comments)
  
SELECT [ItemNumber]
	   ,[ProductName]
      ,'' [PurchaseUnitSymbol]
      ,[ProductGroupId]
      ,[RetailProductCategoryname]
      ,[BOMUnitSymbol]
      ,'' [SearchName]
      ,[SalesSalesTaxItemGroupCode]
      ,''[SalesUnitSymbol]
      ,''[ProductDescription]
      ,[PurchaseSalesTaxItemGroupCode]
      , Drug_id
	  , Factor
	 
	 ,Comments
  --into dbo.[Mx_Product_Master_new]
  FROM [MarinaDynamics365].[dbo].vw_ReleasedProductCreationsV2_auto 

 -- and [ItemNumber] not in (select [ItemNumber] from [dbo].[Mx_Product_Master_new])



 DROP TABLE [MarinaDashboard].DBO.[D365_Mx_Product_Cost_SP_Agent]

SELECT * 
INTO [MarinaDashboard].dbo.[D365_Mx_Product_Cost_SP_Agent]
FROM [MarinaDynamics365].dbo.[Vw_Mx_Product_Cost_SP_Agent]


 



DROP TABLE [MarinaDashboard].DBO.Mx_Product_Master_new_w_Location

SELECT * 
INTO [MarinaDashboard].dbo.Mx_Product_Master_new_w_Location
FROM [MarinaDashboard].dbo.D365_vw_Mx_Product_Master_w_Location



--- for WAREHOUSE SERVER------------------------


DELETE FROM [192.168.70.132].[MarinaWarehouse].[dbo].[Mx_Product_Master_new]


INSERT INTO [192.168.70.132].[MarinaWarehouse].[dbo].[Mx_Product_Master_new]
Select * from [MarinaDynamics365].[dbo].[Mx_Product_Master_new]



delete FROM [192.168.70.132].[MarinaWarehouse].[dbo].[Item_WH_location]

INSERT INTO [192.168.70.132].[MarinaWarehouse].[dbo].[Item_WH_location]
Select * from [MarinaDashboard].[dbo].[vw_WH_Item_Warehouse_Location]





--- for WAREHOUSE SERVER END ------------------------






END
GO
/****** Object:  StoredProcedure [dbo].[SalesOrderLines_Import_from_D365]    Script Date: 30/07/2025 12:27:44 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO







CREATE PROCEDURE [dbo].[SalesOrderLines_Import_from_D365]
AS
BEGIN
   

-- create a table backup for [fConsumption]
delete from [dbo].[fConsumption_temp]

INSERT INTO [dbo].[fConsumption_temp]
           ([RequestedReceiptDate]
           ,[ItemNumber]
           ,[ShippingWarehouseId]
           ,[SalesUnitSymbol]
           ,[OrderedSalesQuantity]
           ,[LineAmount]
           ,[LineDiscountAmount]
           ,[SalesOrderLineStatus]
           ,[UpdateDate])
    
	SELECT  [RequestedReceiptDate]
      ,[ItemNumber]
      ,[ShippingWarehouseId]
      ,[SalesUnitSymbol]
      ,[OrderedSalesQuantity]
      ,[LineAmount]
      ,[LineDiscountAmount]
      ,[SalesOrderLineStatus]
      ,[UpdateDate]
  FROM [MarinaDynamics365].[dbo].[fConsumption]

  --------------------


  ---delete previous 6 days and insert 


   delete FROM [MarinaDynamics365].[dbo].[fConsumption]
 where [RequestedReceiptDate]>=convert(date,getdate()-6,8)

  
INSERT INTO [dbo].[fConsumption]
           ([RequestedReceiptDate]
           ,[ItemNumber]
           ,[ShippingWarehouseId]
           ,[SalesUnitSymbol]
           ,[OrderedSalesQuantity]
           ,[LineAmount]
           ,[LineDiscountAmount]
           ,[SalesOrderLineStatus]
           ,[UpdateDate])

SELECT  [RequestedReceiptDate]
           ,[ItemNumber]
           ,[ShippingWarehouseId]
           ,[SalesUnitSymbol]
           ,cast([OrderedSalesQuantity] as float)
           ,cast([LineAmount] as decimal(8,2))
           ,cast([LineDiscountAmount] as decimal(8,2))
           ,[SalesOrderLineStatus]
           	  ,getdate()
  FROM [MarinaDynamics365].[dbo].[SalesOrderLines]
   where [RequestedReceiptDate]>=convert(date,getdate()-6,8)


   
drop table dbo.[D365_fConsumption]

SELECT [RequestedReceiptDate]
      ,[ItemNumber]
      ,[ShippingWarehouseId]
      ,[SalesUnitSymbol]
      ,[OrderedSalesQuantity]
	  INTO [dbo].[D365_fConsumption]
   FROM [MarinaDynamics365].[dbo].[fConsumption]



    	drop table [D365_Sales_Registers]
		
		
		SELECT *
		INTO [MarinaDynamics365].dbo.[D365_Sales_Registers]
		FROM [MarinaDynamics365].dbo.[D365_vw_Sales_Registers]


		drop table dbo.[Lastest_Sales_per_item_Branch]

SELECT  * into
dbo.[Lastest_Sales_per_item_Branch]
  FROM [MarinaDynamics365].[dbo].[vw_lastest_Sales_per_item_Branch]




END
GO
/****** Object:  StoredProcedure [dbo].[sp_GetTotalLinesPerBranchPerDay]    Script Date: 30/07/2025 12:27:44 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO

CREATE PROCEDURE [dbo].[sp_GetTotalLinesPerBranchPerDay]
AS
BEGIN
    DECLARE @StartDate DATE = DATEADD(DAY, -7, GETDATE()); -- Start date is 7 days ago
    DECLARE @EndDate DATE = GETDATE() ; -- End date is yesterday
    DECLARE @PivotColumns NVARCHAR(MAX);
    DECLARE @DynamicPivotQuery NVARCHAR(MAX);

    -- Generate the list of pivot columns dynamically for dates within the last 7 days
    SET @PivotColumns = '';
    WHILE @StartDate <= @EndDate
    BEGIN
        SET @PivotColumns = @PivotColumns + ', ' + QUOTENAME(CONVERT(VARCHAR(10), @StartDate, 120));
        SET @StartDate = DATEADD(DAY, 1, @StartDate);
    END
    SET @PivotColumns = STUFF(@PivotColumns, 1, 2, ''); -- Remove leading comma and space

    -- Generate the dynamic pivot query
    SET @DynamicPivotQuery = 
        'SELECT [ShippingWarehouseId], Branch, ' + @PivotColumns + '
        FROM
        (
            SELECT 
                [ShippingWarehouseId],
                (SELECT shortname FROM [MarinaDynamics365].[dbo].[Mx_StoreCode] s WHERE s.storecode = f.ShippingWarehouseId) AS Branch,
                '''' AS tr,
                CONVERT(date, [RequestedReceiptDate]) AS [Date],
                COUNT(*) AS TotalLines
            FROM 
                [MarinaDynamics365].[dbo].[fConsumption] f
            WHERE 
                [RequestedReceiptDate] >= DATEADD(DAY, -7, GETDATE()) -- Filter for the last 7 days
            GROUP BY 
                [ShippingWarehouseId],
                CONVERT(date, [RequestedReceiptDate])
        ) AS PivotData
        PIVOT
        (
            SUM(TotalLines)
            FOR [Date] IN (' + @PivotColumns + ')
        ) AS PivotResult;';

    -- Execute the dynamic pivot query
    EXEC sp_executesql @DynamicPivotQuery;
END;

GO
/****** Object:  StoredProcedure [dbo].[sp_GetTotalSalesPerBranchPerDay]    Script Date: 30/07/2025 12:27:44 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO


CREATE PROCEDURE [dbo].[sp_GetTotalSalesPerBranchPerDay]
AS
BEGIN
DECLARE @StartDate DATE = DATEADD(DAY, -7, GETDATE()); -- Start date is 7 days ago
DECLARE @EndDate DATE = GETDATE()-1; -- End date is today
DECLARE @PivotColumns NVARCHAR(MAX);
DECLARE @DynamicPivotQuery NVARCHAR(MAX);

-- Generate the list of pivot columns dynamically for dates within the last 7 days
SET @PivotColumns = '';
WHILE @StartDate <= @EndDate
BEGIN
    SET @PivotColumns = @PivotColumns + ', ' + QUOTENAME(CONVERT(VARCHAR(10), @StartDate, 120));
    SET @StartDate = DATEADD(DAY, 1, @StartDate);
END
SET @PivotColumns = STUFF(@PivotColumns, 1, 2, ''); -- Remove leading comma and space

-- Generate the dynamic pivot query
SET @DynamicPivotQuery = 
    'SELECT [ShippingWarehouseId], Branch,tr' + @PivotColumns + '
    FROM
    (
        SELECT 
            [ShippingWarehouseId],(select shortname  FROM [MarinaDynamics365].[dbo].[Mx_StoreCode] s
			where s.storecode=f.ShippingWarehouseId) Branch,'''' tr,
            CONVERT(date, [RequestedReceiptDate]) AS [Date],
            sum([LineAmount]) AS TotalSales
        FROM 
            [MarinaDynamics365].[dbo].[fConsumption] f
        WHERE 
            [RequestedReceiptDate] >= DATEADD(DAY, -7, GETDATE()) -- Filter for the last 7 days
        GROUP BY 
            [ShippingWarehouseId],
            CONVERT(date, [RequestedReceiptDate])
    ) AS PivotData
    PIVOT
    (
        SUM(TotalSales)
        FOR [Date] IN (' + @PivotColumns + ')
    ) AS PivotResult;';

-- Execute the dynamic pivot query
EXEC sp_executesql @DynamicPivotQuery;
end
GO
/****** Object:  StoredProcedure [dbo].[TO_Dump_Import_from_D365_1Month]    Script Date: 30/07/2025 12:27:44 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO











CREATE PROCEDURE [dbo].[TO_Dump_Import_from_D365_1Month]
AS
BEGIN



  delete  FROM [MarinaDynamics365].[dbo].[TransferOrderHeaders]
  where [TransferOrderNumber] in ( SELECT [TransferOrderNumber] FROM [MarinaDynamics365].[dbo].[TOHeader_1Month])


  INSERT INTO [dbo].[TransferOrderHeaders]
           ([TransferOrderNumber]
           ,[RequestedReceiptDate]
           ,[ShippingWarehouseId]
           ,[ReceivingWarehouseId]
           ,[ShippingAddressName]
           ,[TransferOrderStatus]
           ,[ReceivingAddressName]
           ,[RequestedShippingDate])

     SELECT  [TransferOrderNumber]
      ,convert(varchar,[RequestedReceiptDate])
      ,[ShippingWarehouseId]
      ,[ReceivingWarehouseId]
      ,[ShippingAddressName]
      ,[TransferOrderStatus]
      ,[ReceivingAddressName]
      ,convert(varchar,[RequestedShippingDate])

  FROM [MarinaDynamics365].[dbo].[TOHeader_1Month]






   delete FROM [MarinaDynamics365].[dbo].TransferOrderLines
  where [TransferOrderNumber]  in ( SELECT [TransferOrderNumber] FROM [MarinaDynamics365].[dbo].TOLines_1Month)






  
INSERT INTO [dbo].[TransferOrderLines]
           ([TransferOrderNumber]
           ,[LineNumber]
           ,[TransferQuantity]
           ,[LineStatus]
           ,[ShippingSiteId]
           ,[ItemNumber]
           ,[ShippingWarehouseId]
           ,[RequestedReceiptDate]
           ,[ShippedQuantity]
           ,[ReceivedQuantity]
           ,[ReceivingInventoryLotId]
           ,[ShippingInventoryLotId]
           ,[RemainingShippedQuantity]
           ,[RequestedShippingDate]
           ,[ReceivingTransitInventoryLotId]
           ,[ItemBatchNumber])

	SELECT      [TransferOrderNumber]
           ,[LineNumber]
           ,[TransferQuantity]
           ,[LineStatus]
           ,[ShippingSiteId]
           ,[ItemNumber]
           ,[ShippingWarehouseId]
           ,convert(varchar,[RequestedReceiptDate])
           ,[ShippedQuantity]
           ,[ReceivedQuantity]
           ,[ReceivingInventoryLotId]
           ,[ShippingInventoryLotId]
           ,[RemainingShippedQuantity]
           ,convert(varchar,[RequestedShippingDate])
           ,[ReceivingTransitInventoryLotId]
           ,[ItemBatchNumber]
  FROM [MarinaDynamics365].[dbo].[TOLines_1Month]
	 
	 
END
GO
/****** Object:  StoredProcedure [dbo].[TO_Dump_Import_from_D365_Today]    Script Date: 30/07/2025 12:27:44 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO











CREATE PROCEDURE [dbo].[TO_Dump_Import_from_D365_Today]
AS
BEGIN



  delete  FROM [MarinaDynamics365].[dbo].[TransferOrderHeaders]
  where [TransferOrderNumber] in ( SELECT [TransferOrderNumber] FROM [MarinaDynamics365].[dbo].[TransferOrderHeaders_Today])


  INSERT INTO [dbo].[TransferOrderHeaders]
           ([TransferOrderNumber]
           ,[RequestedReceiptDate]
           ,[ShippingWarehouseId]
           ,[ReceivingWarehouseId]
           ,[ShippingAddressName]
           ,[TransferOrderStatus]
           ,[ReceivingAddressName]
           ,[RequestedShippingDate])

     SELECT  [TransferOrderNumber]
      ,convert(varchar,[RequestedReceiptDate])
      ,[ShippingWarehouseId]
      ,[ReceivingWarehouseId]
      ,[ShippingAddressName]
      ,[TransferOrderStatus]
      ,[ReceivingAddressName]
      ,convert(varchar,[RequestedShippingDate])

  FROM [MarinaDynamics365].[dbo].TransferOrderHeaders_Today






   delete FROM [MarinaDynamics365].[dbo].TransferOrderLines
  where [TransferOrderNumber]  in ( SELECT [TransferOrderNumber] FROM [MarinaDynamics365].[dbo].TransferOrderLines_Today)






  
INSERT INTO [dbo].[TransferOrderLines]
           ([TransferOrderNumber]
           ,[LineNumber]
           ,[TransferQuantity]
           ,[LineStatus]
           ,[ShippingSiteId]
           ,[ItemNumber]
           ,[ShippingWarehouseId]
           ,[RequestedReceiptDate]
           ,[ShippedQuantity]
           ,[ReceivedQuantity]
           ,[ReceivingInventoryLotId]
           ,[ShippingInventoryLotId]
           ,[RemainingShippedQuantity]
           ,[RequestedShippingDate]
           ,[ReceivingTransitInventoryLotId]
           ,[ItemBatchNumber])

	SELECT      [TransferOrderNumber]
           ,[LineNumber]
           ,[TransferQuantity]
           ,[LineStatus]
           ,[ShippingSiteId]
           ,[ItemNumber]
           ,[ShippingWarehouseId]
           ,convert(varchar,[RequestedReceiptDate])
           ,[ShippedQuantity]
           ,[ReceivedQuantity]
           ,[ReceivingInventoryLotId]
           ,[ShippingInventoryLotId]
           ,[RemainingShippedQuantity]
           ,convert(varchar,[RequestedShippingDate])
           ,[ReceivingTransitInventoryLotId]
           ,[ItemBatchNumber]
  FROM [MarinaDynamics365].[dbo].TransferOrderLines_Today
	 
	 
END
GO
/****** Object:  StoredProcedure [dbo].[ValidateOrder_vs_Stocks]    Script Date: 30/07/2025 12:27:44 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO








CREATE PROCEDURE [dbo].[ValidateOrder_vs_Stocks]
AS
BEGIN
    DECLARE @ref VARCHAR(255), -- Declare variable to hold the selected reference
	 @remarks VARCHAR(255),
	  @seq int

    -- Cursor to iterate through the SELECT result
    DECLARE ref_cursor CURSOR FOR
    SELECT distinct [ref]  FROM [MarinaDynamics365].[dbo].[Negtaive_sales_final];

    OPEN ref_cursor;

    -- Fetch the first reference
    FETCH NEXT FROM ref_cursor INTO @ref;

    -- Loop through each reference and perform the INSERT
    WHILE @@FETCH_STATUS = 0
    BEGIN

	SELECT   @remarks= case when sum(cast([Available physical] as decimal(8,2))) <

	    (	SELECT  SUM([Sales qty])
  FROM [MarinaDynamics365].[dbo].[Negtaive_sales_final]
  where [ref]=@ref)  then 'Not enough stock'

  when sum(cast([Available physical] as decimal(8,2))) >

	    (	SELECT  SUM([Sales qty])
  FROM [MarinaDynamics365].[dbo].[Negtaive_sales_final]
  where [ref]=@ref)  then 'More Stock'

  when sum(cast([Available physical] as decimal(8,2))) =

	    (	SELECT  SUM([Sales qty])
  FROM [MarinaDynamics365].[dbo].[Negtaive_sales_final]
  where [ref]=@ref)  then 'Have Equal Stock'

   end
  
    
  FROM [MarinaDynamics365].[dbo].[ON hand Stock3]
   where [Site]+[Item number]=@ref

   group by [Item number]
     
      ,[Site]


	 



 update [MarinaDynamics365].[dbo].[Negtaive_sales_final]
  set [validation]=@remarks,
  On_Hand =  	substring((select [Batch number] + ' - ' + [Available physical]   + ' - '
				from [MarinaDynamics365].[dbo].[ON hand Stock3] o 
				where o.[Item number]=[dbo].[Negtaive_sales_final].[Item number] and o.[Warehouse]=[dbo].[Negtaive_sales_final].[Warehouse] and [Available physical]<>'0'
			
				order by cast([Available physical] as decimal(8,2))- cast([Sales qty] as decimal(8,2)) asc
				for xml path('')), 1, 
				
				(len((select  [Batch number]  + ' - ' + [Available physical] + ' - '
				from [MarinaDynamics365].[dbo].[ON hand Stock3] o 
				where o.[Item number]=[dbo].[Negtaive_sales_final].[Item number] and  o.[Warehouse]=[dbo].[Negtaive_sales_final].[Warehouse] and [Available physical]<>'0'
				
			order by cast([Available physical] as decimal(8,2))-cast([Sales qty] as decimal(8,2)) asc
				for xml path(''))) - 1)) 
	

	

  where   ref=@ref

  

 




	
		 


        -- Fetch the next reference
        FETCH NEXT FROM ref_cursor INTO @ref;
    END

    CLOSE ref_cursor;
    DEALLOCATE ref_cursor;
END
GO
/****** Object:  StoredProcedure [dbo].[ValidateOrder_vs_Stocks_crm]    Script Date: 30/07/2025 12:27:44 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO








CREATE PROCEDURE [dbo].[ValidateOrder_vs_Stocks_crm]
AS
BEGIN
    DECLARE @ref VARCHAR(255), -- Declare variable to hold the selected reference
	 @remarks VARCHAR(255),
	  @seq int

    -- Cursor to iterate through the SELECT result
    DECLARE ref_cursor CURSOR FOR
    SELECT distinct [ref]  FROM [MarinaDynamics365].[dbo].[Negtaive_sales_final_crm];

    OPEN ref_cursor;

    -- Fetch the first reference
    FETCH NEXT FROM ref_cursor INTO @ref;

    -- Loop through each reference and perform the INSERT
    WHILE @@FETCH_STATUS = 0
    BEGIN

	SELECT   @remarks= case when sum(cast([Available physical] as decimal(8,2))) <

	    (	SELECT  SUM([Sales qty])
  FROM [MarinaDynamics365].[dbo].[Negtaive_sales_final_crm]
  where [ref]=@ref)  then 'Not enough stock'

  when sum(cast([Available physical] as decimal(8,2))) >

	    (	SELECT  SUM([Sales qty])
  FROM [MarinaDynamics365].[dbo].[Negtaive_sales_final_crm]
  where [ref]=@ref)  then 'More Stock'

  when sum(cast([Available physical] as decimal(8,2))) =

	 	    (	SELECT  SUM([Sales qty])
  FROM [MarinaDynamics365].[dbo].[Negtaive_sales_final_crm]
  where [ref]=@ref)  
  
 and count([Batch number])=1

  
  
  then 'Have Equal Stock in same batch'

   when sum(cast([Available physical] as decimal(8,2))) =

	    (	SELECT  SUM([Sales qty])
  FROM [MarinaDynamics365].[dbo].[Negtaive_sales_final_crm]
  where [ref]=@ref)  
  
 and count([Batch number])>1

  
  
  then 'Have Equal Stock in other batch'

   end

  
    
FROM [MarinaDynamics365].[dbo].[ON hand Stock3]
   where [Site]+[Item number]=@ref

   group by [Item number]
     
      ,[Site]


	 



 update [MarinaDynamics365].[dbo].[Negtaive_sales_final_crm]
  set [validation]=@remarks,
  On_Hand =  	substring((select [Batch number] + ' - ' + [Available physical]   + ' - '
				from [MarinaDynamics365].[dbo].[ON hand Stock3] o 
				where o.[Item number]=[dbo].[Negtaive_sales_final_crm].[Item number] and o.[Warehouse]=[dbo].[Negtaive_sales_final_crm].[Warehouse] and [Available physical]<>'0'
			
				order by cast([Available physical] as decimal(8,2))- cast([Sales qty] as decimal(8,2)) asc
				for xml path('')), 1, 
				
				(len((select  [Batch number]  + ' - ' + [Available physical] + ' - '
				from [MarinaDynamics365].[dbo].[ON hand Stock3] o 
				where o.[Item number]=[dbo].[Negtaive_sales_final_crm].[Item number] and  o.[Warehouse]=[dbo].[Negtaive_sales_final_crm].[Warehouse] and [Available physical]<>'0'
				
			order by cast([Available physical] as decimal(8,2))-cast([Sales qty] as decimal(8,2)) asc
				for xml path(''))) - 1)) 
	

	

  where   ref=@ref

  

 




	
		 


        -- Fetch the next reference
        FETCH NEXT FROM ref_cursor INTO @ref;
    END

    CLOSE ref_cursor;
    DEALLOCATE ref_cursor;
END
GO
/****** Object:  StoredProcedure [dbo].[ValidateOrder_w_More_Stocks]    Script Date: 30/07/2025 12:27:44 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO


/****** Script for SelectTopNRows command from SSMS  ******/
CREATE PROCEDURE [dbo].[ValidateOrder_w_More_Stocks]
AS
BEGIN
delete from  [Negtaive_sales_final_crm_RAW]

INSERT INTO [dbo].[Negtaive_sales_final_crm_RAW]
           ([Store Code]
           ,[Item number]
           ,[Item Name]
           ,[ref]
           ,[Seq]
           ,[Line_Count]
           ,[Validation]
           ,[On_Hand]
           ,[Selling Batch number]
           ,[Sales qty]
           ,[Found Batch]
           ,[Qty Needed]
           ,[Qty Available]
           ,[Line_Remarks]
           ,[Group_Remarks]
		 ,[Order_id]
      ,[Branch_name])


SELECT  [Store Code]
      ,[Item number]
      ,[Item Name]
       ,[ref]
      ,[Seq]
      ,[Line_Count]
      ,[Validation]
      ,[On_Hand]
	   ,[Batch number] [Selling Batch number]
	   ,[Sales qty]
	  ,    
		case when 
	  --if a matching batch is found with enough stock
	  isnull((select [Batch number] from dbo.[ON hand Stock3] s
	  where s.[Item number]=f.[Item number] and s.Site=f.Site
	  and s.[Batch number]=f.[Batch number]
	  and f.[Sales qty]<=s.[Available physical]),'x')<>'x'
	  
		then 
	
	   (select [Batch number] from dbo.[ON hand Stock3] s
	  where s.[Item number]=f.[Item number] and s.Site=f.Site
	  and s.[Batch number]=f.[Batch number]
	  and f.[Sales qty]<=s.[Available physical])
	  
	  when 

	    isnull((select [Batch number] from dbo.[ON hand Stock3] s
	  where s.[Item number]=f.[Item number] and s.Site=f.Site
	  and s.[Batch number]=f.[Batch number]
	  and f.[Sales qty]<=s.[Available physical]),'x')='x'

	  then


	   (select top 1 [Batch number] from dbo.[ON hand Stock3] s
	  where s.[Item number]=f.[Item number] and s.Site=f.Site
	 -- and s.[Batch number]=f.[Batch number]
	  and f.[Sales qty]<=s.[Available physical] )
	 


	  end [Found Batch]

	  ,	case when 
	  --if a matching batch is found with enough stock
	  isnull((select [Batch number] from dbo.[ON hand Stock3] s
	  where s.[Item number]=f.[Item number] and s.Site=f.Site
	  and s.[Batch number]=f.[Batch number]
	  and f.[Sales qty]<=s.[Available physical]),'x')<>'x'
	  
		then 
	
   [Sales qty]


     when 

	    isnull((select [Batch number] from dbo.[ON hand Stock3] s
	  where s.[Item number]=f.[Item number] and s.Site=f.Site
	  and s.[Batch number]=f.[Batch number]
	  and f.[Sales qty]<=s.[Available physical]),'x')='x'

	  then

	  [Sales qty]



	  end [Qty Needed]
  	
	,	case when 
	  --if a matching batch is found with enough stock
	  isnull((select [Batch number] from dbo.[ON hand Stock3] s
	  where s.[Item number]=f.[Item number] and s.Site=f.Site
	  and s.[Batch number]=f.[Batch number]
	  and f.[Sales qty]<=s.[Available physical]),'x')<>'x'
	  
		then 
	
   (select [Available physical] from dbo.[ON hand Stock3] s
	  where s.[Item number]=f.[Item number] and s.Site=f.Site
	  and s.[Batch number]=f.[Batch number]
	  and f.[Sales qty]<=s.[Available physical])


	    when 

	    isnull((select [Batch number] from dbo.[ON hand Stock3] s
	  where s.[Item number]=f.[Item number] and s.Site=f.Site
	  and s.[Batch number]=f.[Batch number]
	  and f.[Sales qty]<=s.[Available physical]),'x')='x'

	  then


	   (select top 1 [Available physical] from dbo.[ON hand Stock3] s
	  where s.[Item number]=f.[Item number] and s.Site=f.Site
	 -- and s.[Batch number]=f.[Batch number]
	  and f.[Sales qty]<=s.[Available physical] )



	  end [Qty Available]

	  ,case when 
	  --if a matching batch is found with enough stock
	  isnull((select [Batch number] from dbo.[ON hand Stock3] s
	  where s.[Item number]=f.[Item number] and s.Site=f.Site
	  and s.[Batch number]=f.[Batch number]
	  and f.[Sales qty]<=s.[Available physical]),'x')<>'x'
	  
		then 
	
	  'Matching Batch and Qty Found'

	  when 

	    isnull((select [Batch number] from dbo.[ON hand Stock3] s
	  where s.[Item number]=f.[Item number] and s.Site=f.Site
	  and s.[Batch number]=f.[Batch number]
	  and f.[Sales qty]<=s.[Available physical]),'x')='x'

	  then

	  'CRM to be Adjusted'


	     end Line_Remarks
          ,'More Stocks On Hand' Group_Remarks
		  	  ,[Order_id]
      ,[Branch_name]

	--	into [dbo].[Negtaive_sales_final_crm_RAW]
 FROM [MarinaDynamics365].[dbo].[Negtaive_sales_final_crm] f
  where [validation] in ('More Stock','Have Equal Stock in same batch','Have Equal Stock in other batch') and
  isnull([On_Hand],'x')<>'x'


  end
 
GO
/****** Object:  StoredProcedure [dbo].[ZEB_Pre_Assign]    Script Date: 30/07/2025 12:27:44 ******/
SET ANSI_NULLS ON
GO
SET QUOTED_IDENTIFIER ON
GO








CREATE PROCEDURE [dbo].[ZEB_Pre_Assign]
AS
BEGIN
    DECLARE @ref VARCHAR(255); -- Declare variable to hold the selected reference

    -- Cursor to iterate through the SELECT result
    DECLARE ref_cursor CURSOR FOR
    
  select [TransferOrderNumber]

   FROM [MarinaDynamics365].[dbo].[vw_TransferOrderHeaders_Pending_WH] p
   where TransferOrderNumber not in (Select order_id from marinadashboard.dbo.zeb_mobile_master)

    OPEN ref_cursor;

    -- Fetch the first reference
    FETCH NEXT FROM ref_cursor INTO @ref;

    -- Loop through each reference and perform the INSERT
    WHILE @@FETCH_STATUS = 0
    BEGIN






INSERT INTO [dbo].[ZEB_Mobile_Master]
			([Order_id]
		   ,[Orddate]
		   ,[Processed]
		   ,[LocationID]
		   ,[User]
		   ,StaffID
		   ,AssignDate
		   ,[status]
		   ,[Remarks1]
		    ,[StoreNo]
			,[StoreName]
		
	
			)
				  SELECT  [TransferOrderNumber]
      ,[RequestedReceiptDate]
	   ,[ReceivingWarehouseId]+' - '+[ReceivingAddressName]
	   ,[LocationID]
	   ,''
	   ,'System'
	   ,getdate()
	   ,'Pre-Assigned'
	    ,'D365'
	
	   ,case when [ShippingWarehouseId]='WH0001' then 1
	   when [ShippingWarehouseId]='WH0002' then 8 end
	     ,case when [ShippingWarehouseId]='WH0001' then 'Marina'
	   when [ShippingWarehouseId]='WH0002' then '800' end
	 
	   
	

  FROM [MarinaDynamics365].[dbo].[vw_TransferOrderHeaders_Pending_WH]
		   where TransferOrderNumber=@ref	



INSERT INTO [dbo].[ZEB_Mobile_Details_pre]
			( Seq
			,[Order_id]
			  ,[Drug_id]
			  ,[Qty_Ord]
			  ,[DelDate]
			  ,[Retail]
			  ,[Qty_OrdBonus]
			  ,AssignDate
			  ,scan_status
			  ,DrugName
			  ,Category
			   ,[StoreNo]
			 )
				 
	 	 SELECT    ROW_NUMBER() OVER(ORDER BY ProductGroupId asc,ProductName asc) SNo 
	, [TransferOrderNumber]
   ,[ItemNumber]
    ,[TransferQuantity]
	,GETDATE()
	,0
	, [LineNumber]
	,getdate()
    ,ISNULL(substring((select distinct BATCH  +'-'+ convert(varchar,Cast(STOCK as Decimal(6,0)))   + '/'
										from  marinadashboard.dbo.[vw_D365_Stock_Batck_from_PBi_WH] bd
										where bd.ItemNumber=d.[ItemNumber] AND STOCK<>0 and bd.StoreNo=WH

										GROUP BY BATCH,STOCK

										for xml path('')), 1, (len((select distinct BATCH +'-'+ convert(varchar,Cast(STOCK as Decimal(6,0)))   + '/'
										from  marinadashboard.dbo.[vw_D365_Stock_Batck_from_PBi_WH] bd
										where   bd.ItemNumber=d.[ItemNumber]  AND STOCK<>0 and bd.StoreNo=WH
										GROUP BY BATCH,STOCK

										for xml path(''))) - 1)),'0')
	 ,ProductName
	, ProductGroupId
	  ,WH
  
  FROM [MarinaDynamics365].[dbo].[vw_TransferOrderLines_Pending_WH] d
   where TransferOrderNumber=@ref
					

 -- Fetch the next reference
        FETCH NEXT FROM ref_cursor INTO @ref;
    END

    CLOSE ref_cursor;
    DEALLOCATE ref_cursor;
END
GO
EXEC sys.sp_addextendedproperty @name=N'MS_DiagramPane1', @value=N'[0E232FF0-B466-11cf-A24F-00AA00A3EFFF, 1.00]
Begin DesignProperties = 
   Begin PaneConfigurations = 
      Begin PaneConfiguration = 0
         NumPanes = 4
         Configuration = "(H (1[41] 4[20] 2[14] 3) )"
      End
      Begin PaneConfiguration = 1
         NumPanes = 3
         Configuration = "(H (1 [50] 4 [25] 3))"
      End
      Begin PaneConfiguration = 2
         NumPanes = 3
         Configuration = "(H (1 [50] 2 [25] 3))"
      End
      Begin PaneConfiguration = 3
         NumPanes = 3
         Configuration = "(H (4 [30] 2 [40] 3))"
      End
      Begin PaneConfiguration = 4
         NumPanes = 2
         Configuration = "(H (1 [56] 3))"
      End
      Begin PaneConfiguration = 5
         NumPanes = 2
         Configuration = "(H (2 [66] 3))"
      End
      Begin PaneConfiguration = 6
         NumPanes = 2
         Configuration = "(H (4 [50] 3))"
      End
      Begin PaneConfiguration = 7
         NumPanes = 1
         Configuration = "(V (3))"
      End
      Begin PaneConfiguration = 8
         NumPanes = 3
         Configuration = "(H (1[56] 4[18] 2) )"
      End
      Begin PaneConfiguration = 9
         NumPanes = 2
         Configuration = "(H (1 [75] 4))"
      End
      Begin PaneConfiguration = 10
         NumPanes = 2
         Configuration = "(H (1[66] 2) )"
      End
      Begin PaneConfiguration = 11
         NumPanes = 2
         Configuration = "(H (4 [60] 2))"
      End
      Begin PaneConfiguration = 12
         NumPanes = 1
         Configuration = "(H (1) )"
      End
      Begin PaneConfiguration = 13
         NumPanes = 1
         Configuration = "(V (4))"
      End
      Begin PaneConfiguration = 14
         NumPanes = 1
         Configuration = "(V (2))"
      End
      ActivePaneConfig = 0
   End
   Begin DiagramPane = 
      Begin Origin = 
         Top = 0
         Left = 0
      End
      Begin Tables = 
         Begin Table = "Mx_Product_Master_new"
            Begin Extent = 
               Top = 6
               Left = 38
               Bottom = 136
               Right = 304
            End
            DisplayFlags = 280
            TopColumn = 3
         End
         Begin Table = "Vw_Mx_Product_Cost_SP_Agent"
            Begin Extent = 
               Top = 44
               Left = 507
               Bottom = 265
               Right = 927
            End
            DisplayFlags = 280
            TopColumn = 0
         End
      End
   End
   Begin SQLPane = 
   End
   Begin DataPane = 
      Begin ParameterDefaults = ""
      End
      Begin ColumnWidths = 12
         Width = 284
         Width = 1500
         Width = 1500
         Width = 1500
         Width = 1500
         Width = 1500
         Width = 1500
         Width = 1500
         Width = 1500
         Width = 1500
         Width = 1500
         Width = 1500
      End
   End
   Begin CriteriaPane = 
      Begin ColumnWidths = 11
         Column = 1440
         Alias = 900
         Table = 1170
         Output = 720
         Append = 1400
         NewValue = 1170
         SortType = 1350
         SortOrder = 1410
         GroupBy = 1350
         Filter = 1920
         Or = 1350
         Or = 1350
         Or = 1350
      End
   End
End
' , @level0type=N'SCHEMA',@level0name=N'dbo', @level1type=N'VIEW',@level1name=N'D365_vw_Mx_Product_Cat_SP_Cost_Agent'
GO
EXEC sys.sp_addextendedproperty @name=N'MS_DiagramPaneCount', @value=1 , @level0type=N'SCHEMA',@level0name=N'dbo', @level1type=N'VIEW',@level1name=N'D365_vw_Mx_Product_Cat_SP_Cost_Agent'
GO
EXEC sys.sp_addextendedproperty @name=N'MS_DiagramPane1', @value=N'[0E232FF0-B466-11cf-A24F-00AA00A3EFFF, 1.00]
Begin DesignProperties = 
   Begin PaneConfigurations = 
      Begin PaneConfiguration = 0
         NumPanes = 4
         Configuration = "(H (1[40] 4[20] 2[20] 3) )"
      End
      Begin PaneConfiguration = 1
         NumPanes = 3
         Configuration = "(H (1 [50] 4 [25] 3))"
      End
      Begin PaneConfiguration = 2
         NumPanes = 3
         Configuration = "(H (1 [50] 2 [25] 3))"
      End
      Begin PaneConfiguration = 3
         NumPanes = 3
         Configuration = "(H (4 [30] 2 [40] 3))"
      End
      Begin PaneConfiguration = 4
         NumPanes = 2
         Configuration = "(H (1 [56] 3))"
      End
      Begin PaneConfiguration = 5
         NumPanes = 2
         Configuration = "(H (2 [66] 3))"
      End
      Begin PaneConfiguration = 6
         NumPanes = 2
         Configuration = "(H (4 [50] 3))"
      End
      Begin PaneConfiguration = 7
         NumPanes = 1
         Configuration = "(V (3))"
      End
      Begin PaneConfiguration = 8
         NumPanes = 3
         Configuration = "(H (1[56] 4[18] 2) )"
      End
      Begin PaneConfiguration = 9
         NumPanes = 2
         Configuration = "(H (1 [75] 4))"
      End
      Begin PaneConfiguration = 10
         NumPanes = 2
         Configuration = "(H (1[66] 2) )"
      End
      Begin PaneConfiguration = 11
         NumPanes = 2
         Configuration = "(H (4 [60] 2))"
      End
      Begin PaneConfiguration = 12
         NumPanes = 1
         Configuration = "(H (1) )"
      End
      Begin PaneConfiguration = 13
         NumPanes = 1
         Configuration = "(V (4))"
      End
      Begin PaneConfiguration = 14
         NumPanes = 1
         Configuration = "(V (2))"
      End
      ActivePaneConfig = 0
   End
   Begin DiagramPane = 
      Begin Origin = 
         Top = 0
         Left = 0
      End
      Begin Tables = 
         Begin Table = "D365_fConsumption"
            Begin Extent = 
               Top = 6
               Left = 38
               Bottom = 272
               Right = 245
            End
            DisplayFlags = 280
            TopColumn = 0
         End
         Begin Table = "Mx_StoreCode"
            Begin Extent = 
               Top = 175
               Left = 397
               Bottom = 307
               Right = 567
            End
            DisplayFlags = 280
            TopColumn = 0
         End
         Begin Table = "Mx_Product_Master_new"
            Begin Extent = 
               Top = 70
               Left = 606
               Bottom = 334
               Right = 1047
            End
            DisplayFlags = 280
            TopColumn = 3
         End
      End
   End
   Begin SQLPane = 
   End
   Begin DataPane = 
      Begin ParameterDefaults = ""
      End
      Begin ColumnWidths = 9
         Width = 284
         Width = 1500
         Width = 1500
         Width = 1500
         Width = 1500
         Width = 1500
         Width = 1500
         Width = 1500
         Width = 1500
      End
   End
   Begin CriteriaPane = 
      Begin ColumnWidths = 11
         Column = 1440
         Alias = 900
         Table = 1170
         Output = 720
         Append = 1400
         NewValue = 1170
         SortType = 1350
         SortOrder = 1410
         GroupBy = 1350
         Filter = 1350
         Or = 1350
         Or = 1350
         Or = 1350
      End
   End
End
' , @level0type=N'SCHEMA',@level0name=N'dbo', @level1type=N'VIEW',@level1name=N'D365_vw_Sales_Registers'
GO
EXEC sys.sp_addextendedproperty @name=N'MS_DiagramPaneCount', @value=1 , @level0type=N'SCHEMA',@level0name=N'dbo', @level1type=N'VIEW',@level1name=N'D365_vw_Sales_Registers'
GO
EXEC sys.sp_addextendedproperty @name=N'MS_DiagramPane1', @value=N'[0E232FF0-B466-11cf-A24F-00AA00A3EFFF, 1.00]
Begin DesignProperties = 
   Begin PaneConfigurations = 
      Begin PaneConfiguration = 0
         NumPanes = 4
         Configuration = "(H (1[41] 4[28] 2[12] 3) )"
      End
      Begin PaneConfiguration = 1
         NumPanes = 3
         Configuration = "(H (1 [50] 4 [25] 3))"
      End
      Begin PaneConfiguration = 2
         NumPanes = 3
         Configuration = "(H (1 [50] 2 [25] 3))"
      End
      Begin PaneConfiguration = 3
         NumPanes = 3
         Configuration = "(H (4 [30] 2 [40] 3))"
      End
      Begin PaneConfiguration = 4
         NumPanes = 2
         Configuration = "(H (1 [56] 3))"
      End
      Begin PaneConfiguration = 5
         NumPanes = 2
         Configuration = "(H (2 [66] 3))"
      End
      Begin PaneConfiguration = 6
         NumPanes = 2
         Configuration = "(H (4 [50] 3))"
      End
      Begin PaneConfiguration = 7
         NumPanes = 1
         Configuration = "(V (3))"
      End
      Begin PaneConfiguration = 8
         NumPanes = 3
         Configuration = "(H (1[56] 4[18] 2) )"
      End
      Begin PaneConfiguration = 9
         NumPanes = 2
         Configuration = "(H (1 [75] 4))"
      End
      Begin PaneConfiguration = 10
         NumPanes = 2
         Configuration = "(H (1[66] 2) )"
      End
      Begin PaneConfiguration = 11
         NumPanes = 2
         Configuration = "(H (4 [60] 2))"
      End
      Begin PaneConfiguration = 12
         NumPanes = 1
         Configuration = "(H (1) )"
      End
      Begin PaneConfiguration = 13
         NumPanes = 1
         Configuration = "(V (4))"
      End
      Begin PaneConfiguration = 14
         NumPanes = 1
         Configuration = "(V (2))"
      End
      ActivePaneConfig = 0
   End
   Begin DiagramPane = 
      Begin Origin = 
         Top = 0
         Left = 0
      End
      Begin Tables = 
         Begin Table = "D365_fConsumption"
            Begin Extent = 
               Top = 6
               Left = 38
               Bottom = 284
               Right = 280
            End
            DisplayFlags = 280
            TopColumn = 1
         End
         Begin Table = "Mx_Product_Master_new"
            Begin Extent = 
               Top = 0
               Left = 447
               Bottom = 272
               Right = 713
            End
            DisplayFlags = 280
            TopColumn = 3
         End
      End
   End
   Begin SQLPane = 
   End
   Begin DataPane = 
      Begin ParameterDefaults = ""
      End
   End
   Begin CriteriaPane = 
      Begin ColumnWidths = 11
         Column = 4800
         Alias = 900
         Table = 1170
         Output = 720
         Append = 1400
         NewValue = 1170
         SortType = 1350
         SortOrder = 1410
         GroupBy = 1350
         Filter = 1350
         Or = 1350
         Or = 1350
         Or = 1350
      End
   End
End
' , @level0type=N'SCHEMA',@level0name=N'dbo', @level1type=N'VIEW',@level1name=N'vw_D365_fConsumption_Final'
GO
EXEC sys.sp_addextendedproperty @name=N'MS_DiagramPaneCount', @value=1 , @level0type=N'SCHEMA',@level0name=N'dbo', @level1type=N'VIEW',@level1name=N'vw_D365_fConsumption_Final'
GO
EXEC sys.sp_addextendedproperty @name=N'MS_DiagramPane1', @value=N'[0E232FF0-B466-11cf-A24F-00AA00A3EFFF, 1.00]
Begin DesignProperties = 
   Begin PaneConfigurations = 
      Begin PaneConfiguration = 0
         NumPanes = 4
         Configuration = "(H (1[40] 4[20] 2[20] 3) )"
      End
      Begin PaneConfiguration = 1
         NumPanes = 3
         Configuration = "(H (1 [50] 4 [25] 3))"
      End
      Begin PaneConfiguration = 2
         NumPanes = 3
         Configuration = "(H (1 [50] 2 [25] 3))"
      End
      Begin PaneConfiguration = 3
         NumPanes = 3
         Configuration = "(H (4 [30] 2 [40] 3))"
      End
      Begin PaneConfiguration = 4
         NumPanes = 2
         Configuration = "(H (1 [56] 3))"
      End
      Begin PaneConfiguration = 5
         NumPanes = 2
         Configuration = "(H (2 [66] 3))"
      End
      Begin PaneConfiguration = 6
         NumPanes = 2
         Configuration = "(H (4 [50] 3))"
      End
      Begin PaneConfiguration = 7
         NumPanes = 1
         Configuration = "(V (3))"
      End
      Begin PaneConfiguration = 8
         NumPanes = 3
         Configuration = "(H (1[56] 4[18] 2) )"
      End
      Begin PaneConfiguration = 9
         NumPanes = 2
         Configuration = "(H (1 [75] 4))"
      End
      Begin PaneConfiguration = 10
         NumPanes = 2
         Configuration = "(H (1[66] 2) )"
      End
      Begin PaneConfiguration = 11
         NumPanes = 2
         Configuration = "(H (4 [60] 2))"
      End
      Begin PaneConfiguration = 12
         NumPanes = 1
         Configuration = "(H (1) )"
      End
      Begin PaneConfiguration = 13
         NumPanes = 1
         Configuration = "(V (4))"
      End
      Begin PaneConfiguration = 14
         NumPanes = 1
         Configuration = "(V (2))"
      End
      ActivePaneConfig = 0
   End
   Begin DiagramPane = 
      Begin Origin = 
         Top = 0
         Left = 0
      End
      Begin Tables = 
         Begin Table = "Drug_Batch_Stock_ordered_SUM_PUR"
            Begin Extent = 
               Top = 6
               Left = 38
               Bottom = 255
               Right = 364
            End
            DisplayFlags = 280
            TopColumn = 0
         End
      End
   End
   Begin SQLPane = 
   End
   Begin DataPane = 
      Begin ParameterDefaults = ""
      End
      Begin ColumnWidths = 9
         Width = 284
         Width = 1500
         Width = 1500
         Width = 1500
         Width = 1500
         Width = 1500
         Width = 1500
         Width = 1500
         Width = 1500
      End
   End
   Begin CriteriaPane = 
      Begin ColumnWidths = 11
         Column = 1440
         Alias = 900
         Table = 1170
         Output = 720
         Append = 1400
         NewValue = 1170
         SortType = 1350
         SortOrder = 1410
         GroupBy = 1350
         Filter = 1350
         Or = 1350
         Or = 1350
         Or = 1350
      End
   End
End
' , @level0type=N'SCHEMA',@level0name=N'dbo', @level1type=N'VIEW',@level1name=N'vw_Drug_Batch_Stock_ordered_SUM_PUR_WH'
GO
EXEC sys.sp_addextendedproperty @name=N'MS_DiagramPaneCount', @value=1 , @level0type=N'SCHEMA',@level0name=N'dbo', @level1type=N'VIEW',@level1name=N'vw_Drug_Batch_Stock_ordered_SUM_PUR_WH'
GO
EXEC sys.sp_addextendedproperty @name=N'MS_DiagramPane1', @value=N'[0E232FF0-B466-11cf-A24F-00AA00A3EFFF, 1.00]
Begin DesignProperties = 
   Begin PaneConfigurations = 
      Begin PaneConfiguration = 0
         NumPanes = 4
         Configuration = "(H (1[40] 4[20] 2[20] 3) )"
      End
      Begin PaneConfiguration = 1
         NumPanes = 3
         Configuration = "(H (1 [50] 4 [25] 3))"
      End
      Begin PaneConfiguration = 2
         NumPanes = 3
         Configuration = "(H (1 [50] 2 [25] 3))"
      End
      Begin PaneConfiguration = 3
         NumPanes = 3
         Configuration = "(H (4 [30] 2 [40] 3))"
      End
      Begin PaneConfiguration = 4
         NumPanes = 2
         Configuration = "(H (1 [56] 3))"
      End
      Begin PaneConfiguration = 5
         NumPanes = 2
         Configuration = "(H (2 [66] 3))"
      End
      Begin PaneConfiguration = 6
         NumPanes = 2
         Configuration = "(H (4 [50] 3))"
      End
      Begin PaneConfiguration = 7
         NumPanes = 1
         Configuration = "(V (3))"
      End
      Begin PaneConfiguration = 8
         NumPanes = 3
         Configuration = "(H (1[56] 4[18] 2) )"
      End
      Begin PaneConfiguration = 9
         NumPanes = 2
         Configuration = "(H (1 [75] 4))"
      End
      Begin PaneConfiguration = 10
         NumPanes = 2
         Configuration = "(H (1[66] 2) )"
      End
      Begin PaneConfiguration = 11
         NumPanes = 2
         Configuration = "(H (4 [60] 2))"
      End
      Begin PaneConfiguration = 12
         NumPanes = 1
         Configuration = "(H (1) )"
      End
      Begin PaneConfiguration = 13
         NumPanes = 1
         Configuration = "(V (4))"
      End
      Begin PaneConfiguration = 14
         NumPanes = 1
         Configuration = "(V (2))"
      End
      ActivePaneConfig = 0
   End
   Begin DiagramPane = 
      Begin Origin = 
         Top = 0
         Left = 0
      End
      Begin Tables = 
         Begin Table = "VendorsV2"
            Begin Extent = 
               Top = 6
               Left = 38
               Bottom = 267
               Right = 452
            End
            DisplayFlags = 280
            TopColumn = 62
         End
         Begin Table = "LPO_800WHAgents"
            Begin Extent = 
               Top = 6
               Left = 490
               Bottom = 119
               Right = 660
            End
            DisplayFlags = 280
            TopColumn = 0
         End
      End
   End
   Begin SQLPane = 
   End
   Begin DataPane = 
      Begin ParameterDefaults = ""
      End
      Begin ColumnWidths = 9
         Width = 284
         Width = 1500
         Width = 1500
         Width = 1500
         Width = 1500
         Width = 1500
         Width = 1500
         Width = 1500
         Width = 1500
      End
   End
   Begin CriteriaPane = 
      Begin ColumnWidths = 11
         Column = 4695
         Alias = 900
         Table = 1170
         Output = 720
         Append = 1400
         NewValue = 1170
         SortType = 1350
         SortOrder = 1410
         GroupBy = 1350
         Filter = 1350
         Or = 1350
         Or = 1350
         Or = 1350
      End
   End
End
' , @level0type=N'SCHEMA',@level0name=N'dbo', @level1type=N'VIEW',@level1name=N'vw_LPO_WH_Agents'
GO
EXEC sys.sp_addextendedproperty @name=N'MS_DiagramPaneCount', @value=1 , @level0type=N'SCHEMA',@level0name=N'dbo', @level1type=N'VIEW',@level1name=N'vw_LPO_WH_Agents'
GO
EXEC sys.sp_addextendedproperty @name=N'MS_DiagramPane1', @value=N'[0E232FF0-B466-11cf-A24F-00AA00A3EFFF, 1.00]
Begin DesignProperties = 
   Begin PaneConfigurations = 
      Begin PaneConfiguration = 0
         NumPanes = 4
         Configuration = "(H (1[36] 4[27] 2[21] 3) )"
      End
      Begin PaneConfiguration = 1
         NumPanes = 3
         Configuration = "(H (1 [50] 4 [25] 3))"
      End
      Begin PaneConfiguration = 2
         NumPanes = 3
         Configuration = "(H (1 [50] 2 [25] 3))"
      End
      Begin PaneConfiguration = 3
         NumPanes = 3
         Configuration = "(H (4 [30] 2 [40] 3))"
      End
      Begin PaneConfiguration = 4
         NumPanes = 2
         Configuration = "(H (1 [56] 3))"
      End
      Begin PaneConfiguration = 5
         NumPanes = 2
         Configuration = "(H (2 [66] 3))"
      End
      Begin PaneConfiguration = 6
         NumPanes = 2
         Configuration = "(H (4 [50] 3))"
      End
      Begin PaneConfiguration = 7
         NumPanes = 1
         Configuration = "(V (3))"
      End
      Begin PaneConfiguration = 8
         NumPanes = 3
         Configuration = "(H (1[56] 4[18] 2) )"
      End
      Begin PaneConfiguration = 9
         NumPanes = 2
         Configuration = "(H (1 [75] 4))"
      End
      Begin PaneConfiguration = 10
         NumPanes = 2
         Configuration = "(H (1[66] 2) )"
      End
      Begin PaneConfiguration = 11
         NumPanes = 2
         Configuration = "(H (4 [60] 2))"
      End
      Begin PaneConfiguration = 12
         NumPanes = 1
         Configuration = "(H (1) )"
      End
      Begin PaneConfiguration = 13
         NumPanes = 1
         Configuration = "(V (4))"
      End
      Begin PaneConfiguration = 14
         NumPanes = 1
         Configuration = "(V (2))"
      End
      ActivePaneConfig = 0
   End
   Begin DiagramPane = 
      Begin Origin = 
         Top = 0
         Left = 0
      End
      Begin Tables = 
         Begin Table = "Mx_Product_Master_new_w_location"
            Begin Extent = 
               Top = 6
               Left = 38
               Bottom = 301
               Right = 337
            End
            DisplayFlags = 280
            TopColumn = 5
         End
         Begin Table = "MX_Product_MinMax_Price_Vendor_Stock"
            Begin Extent = 
               Top = 211
               Left = 453
               Bottom = 411
               Right = 697
            End
            DisplayFlags = 280
            TopColumn = 9
         End
         Begin Table = "Drug_Batch_Stock_ordered_SUM"
            Begin Extent = 
               Top = 56
               Left = 796
               Bottom = 186
               Right = 966
            End
            DisplayFlags = 280
            TopColumn = 2
         End
         Begin Table = "SALES_ZERO_STOCK_REF_COMBINED_60days"
            Begin Extent = 
               Top = 198
               Left = 802
               Bottom = 311
               Right = 972
            End
            DisplayFlags = 280
            TopColumn = 0
         End
         Begin Table = "SALES_ZERO_STOCK_REF_COMBINED_6mos"
            Begin Extent = 
               Top = 6
               Left = 528
               Bottom = 119
               Right = 698
            End
            DisplayFlags = 280
            TopColumn = 0
         End
      End
   End
   Begin SQLPane = 
   End
   Begin DataPane = 
      Begin ParameterDefaults = ""
      End
      Begin ColumnWidths = 9
         Width = 284
         Width = 1500
         Width = 1500
         Width = 1500
         Width = 1500
         Width = 1500
         Width = 1500
         Width = 1500
         Width = 1500' , @level0type=N'SCHEMA',@level0name=N'dbo', @level1type=N'VIEW',@level1name=N'vw_MIN_MAX_REFERENCE_CALCULATOR'
GO
EXEC sys.sp_addextendedproperty @name=N'MS_DiagramPane2', @value=N'
      End
   End
   Begin CriteriaPane = 
      Begin ColumnWidths = 11
         Column = 6750
         Alias = 2505
         Table = 1170
         Output = 720
         Append = 1400
         NewValue = 1170
         SortType = 1350
         SortOrder = 1410
         GroupBy = 1350
         Filter = 1350
         Or = 1350
         Or = 1350
         Or = 1350
      End
   End
End
' , @level0type=N'SCHEMA',@level0name=N'dbo', @level1type=N'VIEW',@level1name=N'vw_MIN_MAX_REFERENCE_CALCULATOR'
GO
EXEC sys.sp_addextendedproperty @name=N'MS_DiagramPaneCount', @value=2 , @level0type=N'SCHEMA',@level0name=N'dbo', @level1type=N'VIEW',@level1name=N'vw_MIN_MAX_REFERENCE_CALCULATOR'
GO
EXEC sys.sp_addextendedproperty @name=N'MS_DiagramPane1', @value=N'[0E232FF0-B466-11cf-A24F-00AA00A3EFFF, 1.00]
Begin DesignProperties = 
   Begin PaneConfigurations = 
      Begin PaneConfiguration = 0
         NumPanes = 4
         Configuration = "(H (1[40] 4[20] 2[20] 3) )"
      End
      Begin PaneConfiguration = 1
         NumPanes = 3
         Configuration = "(H (1 [50] 4 [25] 3))"
      End
      Begin PaneConfiguration = 2
         NumPanes = 3
         Configuration = "(H (1 [50] 2 [25] 3))"
      End
      Begin PaneConfiguration = 3
         NumPanes = 3
         Configuration = "(H (4 [30] 2 [40] 3))"
      End
      Begin PaneConfiguration = 4
         NumPanes = 2
         Configuration = "(H (1 [56] 3))"
      End
      Begin PaneConfiguration = 5
         NumPanes = 2
         Configuration = "(H (2 [66] 3))"
      End
      Begin PaneConfiguration = 6
         NumPanes = 2
         Configuration = "(H (4 [50] 3))"
      End
      Begin PaneConfiguration = 7
         NumPanes = 1
         Configuration = "(V (3))"
      End
      Begin PaneConfiguration = 8
         NumPanes = 3
         Configuration = "(H (1[56] 4[18] 2) )"
      End
      Begin PaneConfiguration = 9
         NumPanes = 2
         Configuration = "(H (1 [75] 4))"
      End
      Begin PaneConfiguration = 10
         NumPanes = 2
         Configuration = "(H (1[66] 2) )"
      End
      Begin PaneConfiguration = 11
         NumPanes = 2
         Configuration = "(H (4 [60] 2))"
      End
      Begin PaneConfiguration = 12
         NumPanes = 1
         Configuration = "(H (1) )"
      End
      Begin PaneConfiguration = 13
         NumPanes = 1
         Configuration = "(V (4))"
      End
      Begin PaneConfiguration = 14
         NumPanes = 1
         Configuration = "(V (2))"
      End
      ActivePaneConfig = 0
   End
   Begin DiagramPane = 
      Begin Origin = 
         Top = 0
         Left = 0
      End
      Begin Tables = 
         Begin Table = "EcoResCategoryBiEntities"
            Begin Extent = 
               Top = 6
               Left = 38
               Bottom = 253
               Right = 312
            End
            DisplayFlags = 280
            TopColumn = 0
         End
         Begin Table = "EcoResCategoryHierarchyBiEntities"
            Begin Extent = 
               Top = 23
               Left = 590
               Bottom = 285
               Right = 794
            End
            DisplayFlags = 280
            TopColumn = 0
         End
      End
   End
   Begin SQLPane = 
   End
   Begin DataPane = 
      Begin ParameterDefaults = ""
      End
      Begin ColumnWidths = 9
         Width = 284
         Width = 1500
         Width = 1500
         Width = 1500
         Width = 1500
         Width = 1500
         Width = 1500
         Width = 1500
         Width = 1500
      End
   End
   Begin CriteriaPane = 
      Begin ColumnWidths = 11
         Column = 1440
         Alias = 1590
         Table = 1170
         Output = 720
         Append = 1400
         NewValue = 1170
         SortType = 1350
         SortOrder = 1410
         GroupBy = 1350
         Filter = 1350
         Or = 1350
         Or = 1350
         Or = 1350
      End
   End
End
' , @level0type=N'SCHEMA',@level0name=N'dbo', @level1type=N'VIEW',@level1name=N'vw_Mx_BrandNames'
GO
EXEC sys.sp_addextendedproperty @name=N'MS_DiagramPaneCount', @value=1 , @level0type=N'SCHEMA',@level0name=N'dbo', @level1type=N'VIEW',@level1name=N'vw_Mx_BrandNames'
GO
EXEC sys.sp_addextendedproperty @name=N'MS_DiagramPane1', @value=N'[0E232FF0-B466-11cf-A24F-00AA00A3EFFF, 1.00]
Begin DesignProperties = 
   Begin PaneConfigurations = 
      Begin PaneConfiguration = 0
         NumPanes = 4
         Configuration = "(H (1[41] 4[20] 2[11] 3) )"
      End
      Begin PaneConfiguration = 1
         NumPanes = 3
         Configuration = "(H (1 [50] 4 [25] 3))"
      End
      Begin PaneConfiguration = 2
         NumPanes = 3
         Configuration = "(H (1 [50] 2 [25] 3))"
      End
      Begin PaneConfiguration = 3
         NumPanes = 3
         Configuration = "(H (4 [30] 2 [40] 3))"
      End
      Begin PaneConfiguration = 4
         NumPanes = 2
         Configuration = "(H (1 [56] 3))"
      End
      Begin PaneConfiguration = 5
         NumPanes = 2
         Configuration = "(H (2 [66] 3))"
      End
      Begin PaneConfiguration = 6
         NumPanes = 2
         Configuration = "(H (4 [50] 3))"
      End
      Begin PaneConfiguration = 7
         NumPanes = 1
         Configuration = "(V (3))"
      End
      Begin PaneConfiguration = 8
         NumPanes = 3
         Configuration = "(H (1[56] 4[18] 2) )"
      End
      Begin PaneConfiguration = 9
         NumPanes = 2
         Configuration = "(H (1 [75] 4))"
      End
      Begin PaneConfiguration = 10
         NumPanes = 2
         Configuration = "(H (1[66] 2) )"
      End
      Begin PaneConfiguration = 11
         NumPanes = 2
         Configuration = "(H (4 [60] 2))"
      End
      Begin PaneConfiguration = 12
         NumPanes = 1
         Configuration = "(H (1) )"
      End
      Begin PaneConfiguration = 13
         NumPanes = 1
         Configuration = "(V (4))"
      End
      Begin PaneConfiguration = 14
         NumPanes = 1
         Configuration = "(V (2))"
      End
      ActivePaneConfig = 0
   End
   Begin DiagramPane = 
      Begin Origin = 
         Top = 0
         Left = 0
      End
      Begin Tables = 
         Begin Table = "Mx_Product_Master"
            Begin Extent = 
               Top = 6
               Left = 38
               Bottom = 136
               Right = 228
            End
            DisplayFlags = 280
            TopColumn = 2
         End
         Begin Table = "PriceMaster_UploadRaw"
            Begin Extent = 
               Top = 6
               Left = 266
               Bottom = 136
               Right = 523
            End
            DisplayFlags = 280
            TopColumn = 3
         End
      End
   End
   Begin SQLPane = 
   End
   Begin DataPane = 
      Begin ParameterDefaults = ""
      End
      Begin ColumnWidths = 9
         Width = 284
         Width = 1500
         Width = 1500
         Width = 1500
         Width = 1500
         Width = 1500
         Width = 1500
         Width = 1500
         Width = 1500
      End
   End
   Begin CriteriaPane = 
      Begin ColumnWidths = 11
         Column = 1440
         Alias = 900
         Table = 1170
         Output = 720
         Append = 1400
         NewValue = 1170
         SortType = 1350
         SortOrder = 1410
         GroupBy = 1350
         Filter = 1350
         Or = 1350
         Or = 1350
         Or = 1350
      End
   End
End
' , @level0type=N'SCHEMA',@level0name=N'dbo', @level1type=N'VIEW',@level1name=N'vw_Mx_Item_Price_Retail'
GO
EXEC sys.sp_addextendedproperty @name=N'MS_DiagramPaneCount', @value=1 , @level0type=N'SCHEMA',@level0name=N'dbo', @level1type=N'VIEW',@level1name=N'vw_Mx_Item_Price_Retail'
GO
EXEC sys.sp_addextendedproperty @name=N'MS_DiagramPane1', @value=N'[0E232FF0-B466-11cf-A24F-00AA00A3EFFF, 1.00]
Begin DesignProperties = 
   Begin PaneConfigurations = 
      Begin PaneConfiguration = 0
         NumPanes = 4
         Configuration = "(H (1[40] 4[20] 2[20] 3) )"
      End
      Begin PaneConfiguration = 1
         NumPanes = 3
         Configuration = "(H (1 [50] 4 [25] 3))"
      End
      Begin PaneConfiguration = 2
         NumPanes = 3
         Configuration = "(H (1 [50] 2 [25] 3))"
      End
      Begin PaneConfiguration = 3
         NumPanes = 3
         Configuration = "(H (4 [30] 2 [40] 3))"
      End
      Begin PaneConfiguration = 4
         NumPanes = 2
         Configuration = "(H (1 [56] 3))"
      End
      Begin PaneConfiguration = 5
         NumPanes = 2
         Configuration = "(H (2 [66] 3))"
      End
      Begin PaneConfiguration = 6
         NumPanes = 2
         Configuration = "(H (4 [50] 3))"
      End
      Begin PaneConfiguration = 7
         NumPanes = 1
         Configuration = "(V (3))"
      End
      Begin PaneConfiguration = 8
         NumPanes = 3
         Configuration = "(H (1[56] 4[18] 2) )"
      End
      Begin PaneConfiguration = 9
         NumPanes = 2
         Configuration = "(H (1 [75] 4))"
      End
      Begin PaneConfiguration = 10
         NumPanes = 2
         Configuration = "(H (1[66] 2) )"
      End
      Begin PaneConfiguration = 11
         NumPanes = 2
         Configuration = "(H (4 [60] 2))"
      End
      Begin PaneConfiguration = 12
         NumPanes = 1
         Configuration = "(H (1) )"
      End
      Begin PaneConfiguration = 13
         NumPanes = 1
         Configuration = "(V (4))"
      End
      Begin PaneConfiguration = 14
         NumPanes = 1
         Configuration = "(V (2))"
      End
      ActivePaneConfig = 0
   End
   Begin DiagramPane = 
      Begin Origin = 
         Top = 0
         Left = 0
      End
      Begin Tables = 
         Begin Table = "SalesAgreement_LatestPrice"
            Begin Extent = 
               Top = 6
               Left = 38
               Bottom = 136
               Right = 266
            End
            DisplayFlags = 280
            TopColumn = 2
         End
         Begin Table = "Mx_Product_Master_new"
            Begin Extent = 
               Top = 36
               Left = 420
               Bottom = 301
               Right = 686
            End
            DisplayFlags = 280
            TopColumn = 0
         End
      End
   End
   Begin SQLPane = 
   End
   Begin DataPane = 
      Begin ParameterDefaults = ""
      End
      Begin ColumnWidths = 9
         Width = 284
         Width = 1500
         Width = 1500
         Width = 1500
         Width = 1500
         Width = 1500
         Width = 1500
         Width = 1500
         Width = 1500
      End
   End
   Begin CriteriaPane = 
      Begin ColumnWidths = 11
         Column = 1440
         Alias = 900
         Table = 1170
         Output = 720
         Append = 1400
         NewValue = 1170
         SortType = 1350
         SortOrder = 1410
         GroupBy = 1350
         Filter = 1350
         Or = 1350
         Or = 1350
         Or = 1350
      End
   End
End
' , @level0type=N'SCHEMA',@level0name=N'dbo', @level1type=N'VIEW',@level1name=N'vw_Mx_PriceMaster'
GO
EXEC sys.sp_addextendedproperty @name=N'MS_DiagramPaneCount', @value=1 , @level0type=N'SCHEMA',@level0name=N'dbo', @level1type=N'VIEW',@level1name=N'vw_Mx_PriceMaster'
GO
EXEC sys.sp_addextendedproperty @name=N'MS_DiagramPane1', @value=N'[0E232FF0-B466-11cf-A24F-00AA00A3EFFF, 1.00]
Begin DesignProperties = 
   Begin PaneConfigurations = 
      Begin PaneConfiguration = 0
         NumPanes = 4
         Configuration = "(H (1[40] 4[20] 2[20] 3) )"
      End
      Begin PaneConfiguration = 1
         NumPanes = 3
         Configuration = "(H (1 [50] 4 [25] 3))"
      End
      Begin PaneConfiguration = 2
         NumPanes = 3
         Configuration = "(H (1 [50] 2 [25] 3))"
      End
      Begin PaneConfiguration = 3
         NumPanes = 3
         Configuration = "(H (4 [30] 2 [40] 3))"
      End
      Begin PaneConfiguration = 4
         NumPanes = 2
         Configuration = "(H (1 [56] 3))"
      End
      Begin PaneConfiguration = 5
         NumPanes = 2
         Configuration = "(H (2 [66] 3))"
      End
      Begin PaneConfiguration = 6
         NumPanes = 2
         Configuration = "(H (4 [50] 3))"
      End
      Begin PaneConfiguration = 7
         NumPanes = 1
         Configuration = "(V (3))"
      End
      Begin PaneConfiguration = 8
         NumPanes = 3
         Configuration = "(H (1[56] 4[18] 2) )"
      End
      Begin PaneConfiguration = 9
         NumPanes = 2
         Configuration = "(H (1 [75] 4))"
      End
      Begin PaneConfiguration = 10
         NumPanes = 2
         Configuration = "(H (1[66] 2) )"
      End
      Begin PaneConfiguration = 11
         NumPanes = 2
         Configuration = "(H (4 [60] 2))"
      End
      Begin PaneConfiguration = 12
         NumPanes = 1
         Configuration = "(H (1) )"
      End
      Begin PaneConfiguration = 13
         NumPanes = 1
         Configuration = "(V (4))"
      End
      Begin PaneConfiguration = 14
         NumPanes = 1
         Configuration = "(V (2))"
      End
      ActivePaneConfig = 0
   End
   Begin DiagramPane = 
      Begin Origin = 
         Top = -192
         Left = -1375
      End
      Begin Tables = 
         Begin Table = "p"
            Begin Extent = 
               Top = 6
               Left = 38
               Bottom = 255
               Right = 325
            End
            DisplayFlags = 280
            TopColumn = 0
         End
         Begin Table = "pm_new"
            Begin Extent = 
               Top = 198
               Left = 1413
               Bottom = 328
               Right = 1679
            End
            DisplayFlags = 280
            TopColumn = 0
         End
         Begin Table = "pm"
            Begin Extent = 
               Top = 198
               Left = 1717
               Bottom = 328
               Right = 1907
            End
            DisplayFlags = 280
            TopColumn = 0
         End
      End
   End
   Begin SQLPane = 
   End
   Begin DataPane = 
      Begin ParameterDefaults = ""
      End
      Begin ColumnWidths = 9
         Width = 284
         Width = 1500
         Width = 1500
         Width = 1500
         Width = 1500
         Width = 1500
         Width = 1500
         Width = 1500
         Width = 1500
      End
   End
   Begin CriteriaPane = 
      Begin ColumnWidths = 12
         Column = 1440
         Alias = 900
         Table = 1170
         Output = 720
         Append = 1400
         NewValue = 1170
         SortType = 1350
         SortOrder = 1410
         GroupBy = 1350
         Filter = 4935
         Or = 1350
         Or = 1350
         Or = 1350
      End
   End
End
' , @level0type=N'SCHEMA',@level0name=N'dbo', @level1type=N'VIEW',@level1name=N'vw_Mx_PriceMaster2'
GO
EXEC sys.sp_addextendedproperty @name=N'MS_DiagramPaneCount', @value=1 , @level0type=N'SCHEMA',@level0name=N'dbo', @level1type=N'VIEW',@level1name=N'vw_Mx_PriceMaster2'
GO
EXEC sys.sp_addextendedproperty @name=N'MS_DiagramPane1', @value=N'[0E232FF0-B466-11cf-A24F-00AA00A3EFFF, 1.00]
Begin DesignProperties = 
   Begin PaneConfigurations = 
      Begin PaneConfiguration = 0
         NumPanes = 4
         Configuration = "(H (1[41] 4[20] 2[13] 3) )"
      End
      Begin PaneConfiguration = 1
         NumPanes = 3
         Configuration = "(H (1 [50] 4 [25] 3))"
      End
      Begin PaneConfiguration = 2
         NumPanes = 3
         Configuration = "(H (1 [50] 2 [25] 3))"
      End
      Begin PaneConfiguration = 3
         NumPanes = 3
         Configuration = "(H (4 [30] 2 [40] 3))"
      End
      Begin PaneConfiguration = 4
         NumPanes = 2
         Configuration = "(H (1 [56] 3))"
      End
      Begin PaneConfiguration = 5
         NumPanes = 2
         Configuration = "(H (2 [66] 3))"
      End
      Begin PaneConfiguration = 6
         NumPanes = 2
         Configuration = "(H (4 [50] 3))"
      End
      Begin PaneConfiguration = 7
         NumPanes = 1
         Configuration = "(V (3))"
      End
      Begin PaneConfiguration = 8
         NumPanes = 3
         Configuration = "(H (1[56] 4[18] 2) )"
      End
      Begin PaneConfiguration = 9
         NumPanes = 2
         Configuration = "(H (1 [75] 4))"
      End
      Begin PaneConfiguration = 10
         NumPanes = 2
         Configuration = "(H (1[66] 2) )"
      End
      Begin PaneConfiguration = 11
         NumPanes = 2
         Configuration = "(H (4 [60] 2))"
      End
      Begin PaneConfiguration = 12
         NumPanes = 1
         Configuration = "(H (1) )"
      End
      Begin PaneConfiguration = 13
         NumPanes = 1
         Configuration = "(V (4))"
      End
      Begin PaneConfiguration = 14
         NumPanes = 1
         Configuration = "(V (2))"
      End
      ActivePaneConfig = 0
   End
   Begin DiagramPane = 
      Begin Origin = 
         Top = 0
         Left = 0
      End
      Begin Tables = 
         Begin Table = "ProductCategoryAssignments"
            Begin Extent = 
               Top = 194
               Left = 780
               Bottom = 425
               Right = 1042
            End
            DisplayFlags = 280
            TopColumn = 0
         End
         Begin Table = "Mx_Product_Master_new"
            Begin Extent = 
               Top = 6
               Left = 38
               Bottom = 329
               Right = 304
            End
            DisplayFlags = 280
            TopColumn = 0
         End
         Begin Table = "ProductCategoryAssignments_1"
            Begin Extent = 
               Top = 32
               Left = 769
               Bottom = 162
               Right = 1031
            End
            DisplayFlags = 280
            TopColumn = 0
         End
         Begin Table = "ProductCategoryAssignments_2"
            Begin Extent = 
               Top = 257
               Left = 398
               Bottom = 387
               Right = 660
            End
            DisplayFlags = 280
            TopColumn = 0
         End
      End
   End
   Begin SQLPane = 
   End
   Begin DataPane = 
      Begin ParameterDefaults = ""
      End
      Begin ColumnWidths = 9
         Width = 284
         Width = 1500
         Width = 2460
         Width = 1500
         Width = 1500
         Width = 2460
         Width = 1500
         Width = 1500
         Width = 1500
      End
   End
   Begin CriteriaPane = 
      Begin ColumnWidths = 11
         Column = 2730
         Alias = 900
         Table = 1170
         Output = 720
         Append = 1400
         NewValue = 1170
         SortType = 1350
         SortOrder = 1410
         GroupBy = 1350
         Filter = ' , @level0type=N'SCHEMA',@level0name=N'dbo', @level1type=N'VIEW',@level1name=N'vw_Mx_Product_Category'
GO
EXEC sys.sp_addextendedproperty @name=N'MS_DiagramPane2', @value=N'1350
         Or = 1350
         Or = 1350
         Or = 1350
      End
   End
End
' , @level0type=N'SCHEMA',@level0name=N'dbo', @level1type=N'VIEW',@level1name=N'vw_Mx_Product_Category'
GO
EXEC sys.sp_addextendedproperty @name=N'MS_DiagramPaneCount', @value=2 , @level0type=N'SCHEMA',@level0name=N'dbo', @level1type=N'VIEW',@level1name=N'vw_Mx_Product_Category'
GO
EXEC sys.sp_addextendedproperty @name=N'MS_DiagramPane1', @value=N'[0E232FF0-B466-11cf-A24F-00AA00A3EFFF, 1.00]
Begin DesignProperties = 
   Begin PaneConfigurations = 
      Begin PaneConfiguration = 0
         NumPanes = 4
         Configuration = "(H (1[42] 4[20] 2[20] 3) )"
      End
      Begin PaneConfiguration = 1
         NumPanes = 3
         Configuration = "(H (1 [50] 4 [25] 3))"
      End
      Begin PaneConfiguration = 2
         NumPanes = 3
         Configuration = "(H (1 [50] 2 [25] 3))"
      End
      Begin PaneConfiguration = 3
         NumPanes = 3
         Configuration = "(H (4 [30] 2 [40] 3))"
      End
      Begin PaneConfiguration = 4
         NumPanes = 2
         Configuration = "(H (1 [56] 3))"
      End
      Begin PaneConfiguration = 5
         NumPanes = 2
         Configuration = "(H (2 [66] 3))"
      End
      Begin PaneConfiguration = 6
         NumPanes = 2
         Configuration = "(H (4 [50] 3))"
      End
      Begin PaneConfiguration = 7
         NumPanes = 1
         Configuration = "(V (3))"
      End
      Begin PaneConfiguration = 8
         NumPanes = 3
         Configuration = "(H (1[56] 4[18] 2) )"
      End
      Begin PaneConfiguration = 9
         NumPanes = 2
         Configuration = "(H (1 [75] 4))"
      End
      Begin PaneConfiguration = 10
         NumPanes = 2
         Configuration = "(H (1[66] 2) )"
      End
      Begin PaneConfiguration = 11
         NumPanes = 2
         Configuration = "(H (4 [60] 2))"
      End
      Begin PaneConfiguration = 12
         NumPanes = 1
         Configuration = "(H (1) )"
      End
      Begin PaneConfiguration = 13
         NumPanes = 1
         Configuration = "(V (4))"
      End
      Begin PaneConfiguration = 14
         NumPanes = 1
         Configuration = "(V (2))"
      End
      ActivePaneConfig = 0
   End
   Begin DiagramPane = 
      Begin Origin = 
         Top = 0
         Left = 0
      End
      Begin Tables = 
         Begin Table = "MX_Product_Cost_SPrice_Upload_Raw"
            Begin Extent = 
               Top = 8
               Left = 23
               Bottom = 299
               Right = 316
            End
            DisplayFlags = 280
            TopColumn = 0
         End
         Begin Table = "Mx_PriceMaster"
            Begin Extent = 
               Top = 224
               Left = 477
               Bottom = 360
               Right = 661
            End
            DisplayFlags = 280
            TopColumn = 1
         End
         Begin Table = "Mx_Product_Master_new"
            Begin Extent = 
               Top = 7
               Left = 448
               Bottom = 137
               Right = 714
            End
            DisplayFlags = 280
            TopColumn = 2
         End
         Begin Table = "VendorsV2"
            Begin Extent = 
               Top = 120
               Left = 862
               Bottom = 372
               Right = 1402
            End
            DisplayFlags = 280
            TopColumn = 0
         End
      End
   End
   Begin SQLPane = 
   End
   Begin DataPane = 
      Begin ParameterDefaults = ""
      End
      Begin ColumnWidths = 9
         Width = 284
         Width = 1500
         Width = 1500
         Width = 1500
         Width = 1500
         Width = 1500
         Width = 2745
         Width = 1500
         Width = 1500
      End
   End
   Begin CriteriaPane = 
      Begin ColumnWidths = 11
         Column = 3270
         Alias = 3330
         Table = 1170
         Output = 720
         Append = 1400
         NewValue = 1170
         SortType = 1350
         SortOrder = 1410
         GroupBy = 1350
         Filter = 1350
         Or = 1350
 ' , @level0type=N'SCHEMA',@level0name=N'dbo', @level1type=N'VIEW',@level1name=N'Vw_Mx_Product_Cost_SP_Agent'
GO
EXEC sys.sp_addextendedproperty @name=N'MS_DiagramPane2', @value=N'        Or = 1350
         Or = 1350
      End
   End
End
' , @level0type=N'SCHEMA',@level0name=N'dbo', @level1type=N'VIEW',@level1name=N'Vw_Mx_Product_Cost_SP_Agent'
GO
EXEC sys.sp_addextendedproperty @name=N'MS_DiagramPaneCount', @value=2 , @level0type=N'SCHEMA',@level0name=N'dbo', @level1type=N'VIEW',@level1name=N'Vw_Mx_Product_Cost_SP_Agent'
GO
EXEC sys.sp_addextendedproperty @name=N'MS_DiagramPane1', @value=N'[0E232FF0-B466-11cf-A24F-00AA00A3EFFF, 1.00]
Begin DesignProperties = 
   Begin PaneConfigurations = 
      Begin PaneConfiguration = 0
         NumPanes = 4
         Configuration = "(H (1[23] 4[37] 2[24] 3) )"
      End
      Begin PaneConfiguration = 1
         NumPanes = 3
         Configuration = "(H (1 [50] 4 [25] 3))"
      End
      Begin PaneConfiguration = 2
         NumPanes = 3
         Configuration = "(H (1 [50] 2 [25] 3))"
      End
      Begin PaneConfiguration = 3
         NumPanes = 3
         Configuration = "(H (4 [30] 2 [40] 3))"
      End
      Begin PaneConfiguration = 4
         NumPanes = 2
         Configuration = "(H (1 [56] 3))"
      End
      Begin PaneConfiguration = 5
         NumPanes = 2
         Configuration = "(H (2 [66] 3))"
      End
      Begin PaneConfiguration = 6
         NumPanes = 2
         Configuration = "(H (4 [50] 3))"
      End
      Begin PaneConfiguration = 7
         NumPanes = 1
         Configuration = "(V (3))"
      End
      Begin PaneConfiguration = 8
         NumPanes = 3
         Configuration = "(H (1[56] 4[18] 2) )"
      End
      Begin PaneConfiguration = 9
         NumPanes = 2
         Configuration = "(H (1 [75] 4))"
      End
      Begin PaneConfiguration = 10
         NumPanes = 2
         Configuration = "(H (1[66] 2) )"
      End
      Begin PaneConfiguration = 11
         NumPanes = 2
         Configuration = "(H (4 [60] 2))"
      End
      Begin PaneConfiguration = 12
         NumPanes = 1
         Configuration = "(H (1) )"
      End
      Begin PaneConfiguration = 13
         NumPanes = 1
         Configuration = "(V (4))"
      End
      Begin PaneConfiguration = 14
         NumPanes = 1
         Configuration = "(V (2))"
      End
      ActivePaneConfig = 0
   End
   Begin DiagramPane = 
      Begin Origin = 
         Top = -96
         Left = 0
      End
      Begin Tables = 
         Begin Table = "Mx_Product_Master_new_w_location"
            Begin Extent = 
               Top = 1
               Left = 16
               Bottom = 271
               Right = 260
            End
            DisplayFlags = 280
            TopColumn = 0
         End
         Begin Table = "MX_Product_Cost_SPrice_Upload_Raw"
            Begin Extent = 
               Top = 258
               Left = 720
               Bottom = 388
               Right = 915
            End
            DisplayFlags = 280
            TopColumn = 2
         End
         Begin Table = "Unposted_Sales_Invoice"
            Begin Extent = 
               Top = 383
               Left = 316
               Bottom = 496
               Right = 486
            End
            DisplayFlags = 280
            TopColumn = 0
         End
         Begin Table = "vw_TransferOrder_Pending_Sum_BR2WH"
            Begin Extent = 
               Top = 17
               Left = 900
               Bottom = 178
               Right = 1109
            End
            DisplayFlags = 280
            TopColumn = 0
         End
         Begin Table = "SALES_ZERO_STOCK_REF_COMBINED_60days"
            Begin Extent = 
               Top = 253
               Left = 420
               Bottom = 366
               Right = 590
            End
            DisplayFlags = 280
            TopColumn = 0
         End
         Begin Table = "Drug_Batch_Stock_ordered_SUM"
            Begin Extent = 
               Top = 203
               Left = 938
               Bottom = 333
               Right = 1108
            End
            DisplayFlags = 280
            TopColumn = 2
         End
         Begin Table = "Mx_Min_Max_Raw_Upload"
            Begin Exten' , @level0type=N'SCHEMA',@level0name=N'dbo', @level1type=N'VIEW',@level1name=N'vw_MX_Product_MinMax_Price_Vendor_Stock'
GO
EXEC sys.sp_addextendedproperty @name=N'MS_DiagramPane2', @value=N't = 
               Top = 3
               Left = 618
               Bottom = 133
               Right = 788
            End
            DisplayFlags = 280
            TopColumn = 0
         End
      End
   End
   Begin SQLPane = 
   End
   Begin DataPane = 
      Begin ParameterDefaults = ""
      End
      Begin ColumnWidths = 15
         Width = 284
         Width = 1500
         Width = 1500
         Width = 1500
         Width = 1500
         Width = 1500
         Width = 1500
         Width = 1500
         Width = 1500
         Width = 1500
         Width = 1500
         Width = 1500
         Width = 1500
         Width = 1500
         Width = 1500
      End
   End
   Begin CriteriaPane = 
      Begin ColumnWidths = 11
         Column = 4125
         Alias = 1815
         Table = 1170
         Output = 720
         Append = 1400
         NewValue = 1170
         SortType = 1350
         SortOrder = 1410
         GroupBy = 1350
         Filter = 1350
         Or = 1350
         Or = 1350
         Or = 1350
      End
   End
End
' , @level0type=N'SCHEMA',@level0name=N'dbo', @level1type=N'VIEW',@level1name=N'vw_MX_Product_MinMax_Price_Vendor_Stock'
GO
EXEC sys.sp_addextendedproperty @name=N'MS_DiagramPaneCount', @value=2 , @level0type=N'SCHEMA',@level0name=N'dbo', @level1type=N'VIEW',@level1name=N'vw_MX_Product_MinMax_Price_Vendor_Stock'
GO
EXEC sys.sp_addextendedproperty @name=N'MS_DiagramPane1', @value=N'[0E232FF0-B466-11cf-A24F-00AA00A3EFFF, 1.00]
Begin DesignProperties = 
   Begin PaneConfigurations = 
      Begin PaneConfiguration = 0
         NumPanes = 4
         Configuration = "(H (1[51] 4[17] 2[17] 3) )"
      End
      Begin PaneConfiguration = 1
         NumPanes = 3
         Configuration = "(H (1 [50] 4 [25] 3))"
      End
      Begin PaneConfiguration = 2
         NumPanes = 3
         Configuration = "(H (1 [50] 2 [25] 3))"
      End
      Begin PaneConfiguration = 3
         NumPanes = 3
         Configuration = "(H (4 [30] 2 [40] 3))"
      End
      Begin PaneConfiguration = 4
         NumPanes = 2
         Configuration = "(H (1 [56] 3))"
      End
      Begin PaneConfiguration = 5
         NumPanes = 2
         Configuration = "(H (2 [66] 3))"
      End
      Begin PaneConfiguration = 6
         NumPanes = 2
         Configuration = "(H (4 [50] 3))"
      End
      Begin PaneConfiguration = 7
         NumPanes = 1
         Configuration = "(V (3))"
      End
      Begin PaneConfiguration = 8
         NumPanes = 3
         Configuration = "(H (1[56] 4[18] 2) )"
      End
      Begin PaneConfiguration = 9
         NumPanes = 2
         Configuration = "(H (1 [75] 4))"
      End
      Begin PaneConfiguration = 10
         NumPanes = 2
         Configuration = "(H (1[66] 2) )"
      End
      Begin PaneConfiguration = 11
         NumPanes = 2
         Configuration = "(H (4 [60] 2))"
      End
      Begin PaneConfiguration = 12
         NumPanes = 1
         Configuration = "(H (1) )"
      End
      Begin PaneConfiguration = 13
         NumPanes = 1
         Configuration = "(V (4))"
      End
      Begin PaneConfiguration = 14
         NumPanes = 1
         Configuration = "(V (2))"
      End
      ActivePaneConfig = 0
   End
   Begin DiagramPane = 
      Begin Origin = 
         Top = 0
         Left = 0
      End
      Begin Tables = 
         Begin Table = "Mx_Product_Master_new_w_location"
            Begin Extent = 
               Top = 0
               Left = 13
               Bottom = 130
               Right = 257
            End
            DisplayFlags = 280
            TopColumn = 6
         End
         Begin Table = "vw_TransferOrder_Pending_Sum_created"
            Begin Extent = 
               Top = 53
               Left = 999
               Bottom = 166
               Right = 1208
            End
            DisplayFlags = 280
            TopColumn = 0
         End
         Begin Table = "Drug_Batch_Stock_ordered_SUM_1"
            Begin Extent = 
               Top = 238
               Left = 66
               Bottom = 368
               Right = 236
            End
            DisplayFlags = 280
            TopColumn = 0
         End
         Begin Table = "vw_UNPOSTED_ITEMS_Sum_for_ORder"
            Begin Extent = 
               Top = 359
               Left = 812
               Bottom = 507
               Right = 982
            End
            DisplayFlags = 280
            TopColumn = 1
         End
         Begin Table = "Mx_Product_Warehouse_Locations"
            Begin Extent = 
               Top = 227
               Left = 307
               Bottom = 323
               Right = 595
            End
            DisplayFlags = 280
            TopColumn = 0
         End
         Begin Table = "MX_Product_Cost_SPrice_Upload_Raw"
            Begin Extent = 
               Top = 202
               Left = 712
               Bottom = 332
               Right = 907
            End
            DisplayFlags = 280
            TopColumn = 2
         End
         Begin Table = "Unposted_Sales_Invoice"
            Begin E' , @level0type=N'SCHEMA',@level0name=N'dbo', @level1type=N'VIEW',@level1name=N'vw_MX_Product_MinMax_Price_Vendor_Stock_re_order'
GO
EXEC sys.sp_addextendedproperty @name=N'MS_DiagramPane2', @value=N'xtent = 
               Top = 365
               Left = 419
               Bottom = 510
               Right = 656
            End
            DisplayFlags = 280
            TopColumn = 0
         End
         Begin Table = "vw_TransferOrder_Pending_Sum"
            Begin Extent = 
               Top = 159
               Left = 1096
               Bottom = 289
               Right = 1463
            End
            DisplayFlags = 280
            TopColumn = 0
         End
         Begin Table = "SALES_ZERO_STOCK_REF_COMBINED_60days"
            Begin Extent = 
               Top = 315
               Left = 1081
               Bottom = 428
               Right = 1251
            End
            DisplayFlags = 280
            TopColumn = 0
         End
         Begin Table = "Drug_Batch_Stock_ordered_SUM"
            Begin Extent = 
               Top = 6
               Left = 690
               Bottom = 136
               Right = 860
            End
            DisplayFlags = 280
            TopColumn = 2
         End
         Begin Table = "Mx_Min_Max_Raw_Upload"
            Begin Extent = 
               Top = 370
               Left = 171
               Bottom = 500
               Right = 341
            End
            DisplayFlags = 280
            TopColumn = 0
         End
      End
   End
   Begin SQLPane = 
   End
   Begin DataPane = 
      Begin ParameterDefaults = ""
      End
      Begin ColumnWidths = 11
         Width = 284
         Width = 1500
         Width = 1500
         Width = 1500
         Width = 1500
         Width = 1500
         Width = 1500
         Width = 1500
         Width = 1500
         Width = 1500
         Width = 1500
      End
   End
   Begin CriteriaPane = 
      Begin ColumnWidths = 11
         Column = 7335
         Alias = 3840
         Table = 1170
         Output = 720
         Append = 1400
         NewValue = 1170
         SortType = 1350
         SortOrder = 1410
         GroupBy = 1350
         Filter = 1350
         Or = 1350
         Or = 1350
         Or = 1350
      End
   End
End
' , @level0type=N'SCHEMA',@level0name=N'dbo', @level1type=N'VIEW',@level1name=N'vw_MX_Product_MinMax_Price_Vendor_Stock_re_order'
GO
EXEC sys.sp_addextendedproperty @name=N'MS_DiagramPaneCount', @value=2 , @level0type=N'SCHEMA',@level0name=N'dbo', @level1type=N'VIEW',@level1name=N'vw_MX_Product_MinMax_Price_Vendor_Stock_re_order'
GO
EXEC sys.sp_addextendedproperty @name=N'MS_DiagramPane1', @value=N'[0E232FF0-B466-11cf-A24F-00AA00A3EFFF, 1.00]
Begin DesignProperties = 
   Begin PaneConfigurations = 
      Begin PaneConfiguration = 0
         NumPanes = 4
         Configuration = "(H (1[40] 4[20] 2[20] 3) )"
      End
      Begin PaneConfiguration = 1
         NumPanes = 3
         Configuration = "(H (1 [50] 4 [25] 3))"
      End
      Begin PaneConfiguration = 2
         NumPanes = 3
         Configuration = "(H (1 [50] 2 [25] 3))"
      End
      Begin PaneConfiguration = 3
         NumPanes = 3
         Configuration = "(H (4 [30] 2 [40] 3))"
      End
      Begin PaneConfiguration = 4
         NumPanes = 2
         Configuration = "(H (1 [56] 3))"
      End
      Begin PaneConfiguration = 5
         NumPanes = 2
         Configuration = "(H (2 [66] 3))"
      End
      Begin PaneConfiguration = 6
         NumPanes = 2
         Configuration = "(H (4 [50] 3))"
      End
      Begin PaneConfiguration = 7
         NumPanes = 1
         Configuration = "(V (3))"
      End
      Begin PaneConfiguration = 8
         NumPanes = 3
         Configuration = "(H (1[56] 4[18] 2) )"
      End
      Begin PaneConfiguration = 9
         NumPanes = 2
         Configuration = "(H (1 [75] 4))"
      End
      Begin PaneConfiguration = 10
         NumPanes = 2
         Configuration = "(H (1[66] 2) )"
      End
      Begin PaneConfiguration = 11
         NumPanes = 2
         Configuration = "(H (4 [60] 2))"
      End
      Begin PaneConfiguration = 12
         NumPanes = 1
         Configuration = "(H (1) )"
      End
      Begin PaneConfiguration = 13
         NumPanes = 1
         Configuration = "(V (4))"
      End
      Begin PaneConfiguration = 14
         NumPanes = 1
         Configuration = "(V (2))"
      End
      ActivePaneConfig = 0
   End
   Begin DiagramPane = 
      Begin Origin = 
         Top = 0
         Left = 0
      End
      Begin Tables = 
         Begin Table = "Mx_Product_Master_new_w_location"
            Begin Extent = 
               Top = 6
               Left = 38
               Bottom = 136
               Right = 282
            End
            DisplayFlags = 280
            TopColumn = 0
         End
         Begin Table = "MX_Product_Cost_SPrice_Upload_Raw"
            Begin Extent = 
               Top = 138
               Left = 38
               Bottom = 268
               Right = 233
            End
            DisplayFlags = 280
            TopColumn = 0
         End
         Begin Table = "Drug_Batch_Stock_ordered_SUM_1"
            Begin Extent = 
               Top = 138
               Left = 271
               Bottom = 268
               Right = 441
            End
            DisplayFlags = 280
            TopColumn = 0
         End
         Begin Table = "vw_TransferOrder_Pending_Sum"
            Begin Extent = 
               Top = 270
               Left = 246
               Bottom = 383
               Right = 455
            End
            DisplayFlags = 280
            TopColumn = 0
         End
         Begin Table = "Drug_Batch_Stock_ordered_SUM"
            Begin Extent = 
               Top = 384
               Left = 246
               Bottom = 514
               Right = 416
            End
            DisplayFlags = 280
            TopColumn = 1
         End
         Begin Table = "Mx_Min_Max_Raw_Upload"
            Begin Extent = 
               Top = 498
               Left = 38
               Bottom = 628
               Right = 208
            End
            DisplayFlags = 280
            TopColumn = 0
         End
      End
   End
   Begin SQLPane = 
   End
   Begin DataPane = 
      Begin Paramet' , @level0type=N'SCHEMA',@level0name=N'dbo', @level1type=N'VIEW',@level1name=N'vw_MX_Product_MinMax_Price_Vendor_Stock_re_order_no_CONS'
GO
EXEC sys.sp_addextendedproperty @name=N'MS_DiagramPane2', @value=N'erDefaults = ""
      End
   End
   Begin CriteriaPane = 
      Begin ColumnWidths = 11
         Column = 1440
         Alias = 900
         Table = 1170
         Output = 720
         Append = 1400
         NewValue = 1170
         SortType = 1350
         SortOrder = 1410
         GroupBy = 1350
         Filter = 1350
         Or = 1350
         Or = 1350
         Or = 1350
      End
   End
End
' , @level0type=N'SCHEMA',@level0name=N'dbo', @level1type=N'VIEW',@level1name=N'vw_MX_Product_MinMax_Price_Vendor_Stock_re_order_no_CONS'
GO
EXEC sys.sp_addextendedproperty @name=N'MS_DiagramPaneCount', @value=2 , @level0type=N'SCHEMA',@level0name=N'dbo', @level1type=N'VIEW',@level1name=N'vw_MX_Product_MinMax_Price_Vendor_Stock_re_order_no_CONS'
GO
EXEC sys.sp_addextendedproperty @name=N'MS_DiagramPane1', @value=N'[0E232FF0-B466-11cf-A24F-00AA00A3EFFF, 1.00]
Begin DesignProperties = 
   Begin PaneConfigurations = 
      Begin PaneConfiguration = 0
         NumPanes = 4
         Configuration = "(H (1[22] 4[32] 2[12] 3) )"
      End
      Begin PaneConfiguration = 1
         NumPanes = 3
         Configuration = "(H (1 [50] 4 [25] 3))"
      End
      Begin PaneConfiguration = 2
         NumPanes = 3
         Configuration = "(H (1 [50] 2 [25] 3))"
      End
      Begin PaneConfiguration = 3
         NumPanes = 3
         Configuration = "(H (4 [30] 2 [40] 3))"
      End
      Begin PaneConfiguration = 4
         NumPanes = 2
         Configuration = "(H (1 [56] 3))"
      End
      Begin PaneConfiguration = 5
         NumPanes = 2
         Configuration = "(H (2 [66] 3))"
      End
      Begin PaneConfiguration = 6
         NumPanes = 2
         Configuration = "(H (4 [50] 3))"
      End
      Begin PaneConfiguration = 7
         NumPanes = 1
         Configuration = "(V (3))"
      End
      Begin PaneConfiguration = 8
         NumPanes = 3
         Configuration = "(H (1[56] 4[18] 2) )"
      End
      Begin PaneConfiguration = 9
         NumPanes = 2
         Configuration = "(H (1 [75] 4))"
      End
      Begin PaneConfiguration = 10
         NumPanes = 2
         Configuration = "(H (1[66] 2) )"
      End
      Begin PaneConfiguration = 11
         NumPanes = 2
         Configuration = "(H (4 [60] 2))"
      End
      Begin PaneConfiguration = 12
         NumPanes = 1
         Configuration = "(H (1) )"
      End
      Begin PaneConfiguration = 13
         NumPanes = 1
         Configuration = "(V (4))"
      End
      Begin PaneConfiguration = 14
         NumPanes = 1
         Configuration = "(V (2))"
      End
      ActivePaneConfig = 0
   End
   Begin DiagramPane = 
      Begin Origin = 
         Top = 0
         Left = 0
      End
      Begin Tables = 
         Begin Table = "Mx_Product_Master"
            Begin Extent = 
               Top = 6
               Left = 38
               Bottom = 136
               Right = 228
            End
            DisplayFlags = 280
            TopColumn = 0
         End
         Begin Table = "ItemStockTotal_UploadRaw"
            Begin Extent = 
               Top = 6
               Left = 266
               Bottom = 136
               Right = 567
            End
            DisplayFlags = 280
            TopColumn = 1
         End
         Begin Table = "Mx_StoreCode"
            Begin Extent = 
               Top = 6
               Left = 605
               Bottom = 163
               Right = 794
            End
            DisplayFlags = 280
            TopColumn = 1
         End
      End
   End
   Begin SQLPane = 
   End
   Begin DataPane = 
      Begin ParameterDefaults = ""
      End
      Begin ColumnWidths = 9
         Width = 284
         Width = 1500
         Width = 1500
         Width = 1500
         Width = 1500
         Width = 1500
         Width = 1500
         Width = 1500
         Width = 1500
      End
   End
   Begin CriteriaPane = 
      Begin ColumnWidths = 11
         Column = 1440
         Alias = 900
         Table = 1170
         Output = 720
         Append = 1400
         NewValue = 1170
         SortType = 1350
         SortOrder = 1410
         GroupBy = 1350
         Filter = 1350
         Or = 1350
         Or = 1350
         Or = 1350
      End
   End
End
' , @level0type=N'SCHEMA',@level0name=N'dbo', @level1type=N'VIEW',@level1name=N'vw_Mx_Stocks_by_Location'
GO
EXEC sys.sp_addextendedproperty @name=N'MS_DiagramPaneCount', @value=1 , @level0type=N'SCHEMA',@level0name=N'dbo', @level1type=N'VIEW',@level1name=N'vw_Mx_Stocks_by_Location'
GO
EXEC sys.sp_addextendedproperty @name=N'MS_DiagramPane1', @value=N'[0E232FF0-B466-11cf-A24F-00AA00A3EFFF, 1.00]
Begin DesignProperties = 
   Begin PaneConfigurations = 
      Begin PaneConfiguration = 0
         NumPanes = 4
         Configuration = "(H (1[40] 4[20] 2[20] 3) )"
      End
      Begin PaneConfiguration = 1
         NumPanes = 3
         Configuration = "(H (1 [50] 4 [25] 3))"
      End
      Begin PaneConfiguration = 2
         NumPanes = 3
         Configuration = "(H (1 [50] 2 [25] 3))"
      End
      Begin PaneConfiguration = 3
         NumPanes = 3
         Configuration = "(H (4 [30] 2 [40] 3))"
      End
      Begin PaneConfiguration = 4
         NumPanes = 2
         Configuration = "(H (1 [56] 3))"
      End
      Begin PaneConfiguration = 5
         NumPanes = 2
         Configuration = "(H (2 [66] 3))"
      End
      Begin PaneConfiguration = 6
         NumPanes = 2
         Configuration = "(H (4 [50] 3))"
      End
      Begin PaneConfiguration = 7
         NumPanes = 1
         Configuration = "(V (3))"
      End
      Begin PaneConfiguration = 8
         NumPanes = 3
         Configuration = "(H (1[56] 4[18] 2) )"
      End
      Begin PaneConfiguration = 9
         NumPanes = 2
         Configuration = "(H (1 [75] 4))"
      End
      Begin PaneConfiguration = 10
         NumPanes = 2
         Configuration = "(H (1[66] 2) )"
      End
      Begin PaneConfiguration = 11
         NumPanes = 2
         Configuration = "(H (4 [60] 2))"
      End
      Begin PaneConfiguration = 12
         NumPanes = 1
         Configuration = "(H (1) )"
      End
      Begin PaneConfiguration = 13
         NumPanes = 1
         Configuration = "(V (4))"
      End
      Begin PaneConfiguration = 14
         NumPanes = 1
         Configuration = "(V (2))"
      End
      ActivePaneConfig = 0
   End
   Begin DiagramPane = 
      Begin Origin = 
         Top = 0
         Left = 0
      End
      Begin Tables = 
         Begin Table = "Mx_Product_Master_new_w_location"
            Begin Extent = 
               Top = 6
               Left = 38
               Bottom = 312
               Right = 282
            End
            DisplayFlags = 280
            TopColumn = 0
         End
         Begin Table = "vw_Drug_Batch_Stock_ordered_SUM"
            Begin Extent = 
               Top = 86
               Left = 559
               Bottom = 216
               Right = 729
            End
            DisplayFlags = 280
            TopColumn = 2
         End
      End
   End
   Begin SQLPane = 
   End
   Begin DataPane = 
      Begin ParameterDefaults = ""
      End
      Begin ColumnWidths = 9
         Width = 284
         Width = 1500
         Width = 1500
         Width = 1500
         Width = 1500
         Width = 1500
         Width = 1500
         Width = 1500
         Width = 1500
      End
   End
   Begin CriteriaPane = 
      Begin ColumnWidths = 11
         Column = 2595
         Alias = 900
         Table = 1170
         Output = 720
         Append = 1400
         NewValue = 1170
         SortType = 1350
         SortOrder = 1410
         GroupBy = 1350
         Filter = 1350
         Or = 1350
         Or = 1350
         Or = 1350
      End
   End
End
' , @level0type=N'SCHEMA',@level0name=N'dbo', @level1type=N'VIEW',@level1name=N'vw_Mx_Stocks_by_Location_V2'
GO
EXEC sys.sp_addextendedproperty @name=N'MS_DiagramPaneCount', @value=1 , @level0type=N'SCHEMA',@level0name=N'dbo', @level1type=N'VIEW',@level1name=N'vw_Mx_Stocks_by_Location_V2'
GO
EXEC sys.sp_addextendedproperty @name=N'MS_DiagramPane1', @value=N'[0E232FF0-B466-11cf-A24F-00AA00A3EFFF, 1.00]
Begin DesignProperties = 
   Begin PaneConfigurations = 
      Begin PaneConfiguration = 0
         NumPanes = 4
         Configuration = "(H (1[41] 4[20] 2[9] 3) )"
      End
      Begin PaneConfiguration = 1
         NumPanes = 3
         Configuration = "(H (1 [50] 4 [25] 3))"
      End
      Begin PaneConfiguration = 2
         NumPanes = 3
         Configuration = "(H (1 [50] 2 [25] 3))"
      End
      Begin PaneConfiguration = 3
         NumPanes = 3
         Configuration = "(H (4 [30] 2 [40] 3))"
      End
      Begin PaneConfiguration = 4
         NumPanes = 2
         Configuration = "(H (1 [56] 3))"
      End
      Begin PaneConfiguration = 5
         NumPanes = 2
         Configuration = "(H (2 [66] 3))"
      End
      Begin PaneConfiguration = 6
         NumPanes = 2
         Configuration = "(H (4 [50] 3))"
      End
      Begin PaneConfiguration = 7
         NumPanes = 1
         Configuration = "(V (3))"
      End
      Begin PaneConfiguration = 8
         NumPanes = 3
         Configuration = "(H (1[56] 4[18] 2) )"
      End
      Begin PaneConfiguration = 9
         NumPanes = 2
         Configuration = "(H (1 [75] 4))"
      End
      Begin PaneConfiguration = 10
         NumPanes = 2
         Configuration = "(H (1[66] 2) )"
      End
      Begin PaneConfiguration = 11
         NumPanes = 2
         Configuration = "(H (4 [60] 2))"
      End
      Begin PaneConfiguration = 12
         NumPanes = 1
         Configuration = "(H (1) )"
      End
      Begin PaneConfiguration = 13
         NumPanes = 1
         Configuration = "(V (4))"
      End
      Begin PaneConfiguration = 14
         NumPanes = 1
         Configuration = "(V (2))"
      End
      ActivePaneConfig = 0
   End
   Begin DiagramPane = 
      Begin Origin = 
         Top = 0
         Left = 0
      End
      Begin Tables = 
         Begin Table = "PostdatedChecks"
            Begin Extent = 
               Top = 6
               Left = 38
               Bottom = 309
               Right = 407
            End
            DisplayFlags = 280
            TopColumn = 0
         End
         Begin Table = "VendorsV2"
            Begin Extent = 
               Top = 135
               Left = 439
               Bottom = 312
               Right = 853
            End
            DisplayFlags = 280
            TopColumn = 123
         End
         Begin Table = "VendorPaymentJournalLines"
            Begin Extent = 
               Top = 6
               Left = 847
               Bottom = 228
               Right = 1197
            End
            DisplayFlags = 280
            TopColumn = 82
         End
      End
   End
   Begin SQLPane = 
   End
   Begin DataPane = 
      Begin ParameterDefaults = ""
      End
      Begin ColumnWidths = 13
         Width = 284
         Width = 1500
         Width = 3015
         Width = 3570
         Width = 4665
         Width = 1500
         Width = 3060
         Width = 2835
         Width = 1500
         Width = 1500
         Width = 2970
         Width = 1500
         Width = 1500
      End
   End
   Begin CriteriaPane = 
      Begin ColumnWidths = 11
         Column = 2835
         Alias = 900
         Table = 1170
         Output = 720
         Append = 1400
         NewValue = 1170
         SortType = 1350
         SortOrder = 1410
         GroupBy = 1350
         Filter = 1350
         Or = 1350
         Or = 1350
         Or = 1350
      End
   End
End
' , @level0type=N'SCHEMA',@level0name=N'dbo', @level1type=N'VIEW',@level1name=N'vw_PostDatedChecks_Details'
GO
EXEC sys.sp_addextendedproperty @name=N'MS_DiagramPaneCount', @value=1 , @level0type=N'SCHEMA',@level0name=N'dbo', @level1type=N'VIEW',@level1name=N'vw_PostDatedChecks_Details'
GO
EXEC sys.sp_addextendedproperty @name=N'MS_DiagramPane1', @value=N'[0E232FF0-B466-11cf-A24F-00AA00A3EFFF, 1.00]
Begin DesignProperties = 
   Begin PaneConfigurations = 
      Begin PaneConfiguration = 0
         NumPanes = 4
         Configuration = "(H (1[40] 4[20] 2[20] 3) )"
      End
      Begin PaneConfiguration = 1
         NumPanes = 3
         Configuration = "(H (1 [50] 4 [25] 3))"
      End
      Begin PaneConfiguration = 2
         NumPanes = 3
         Configuration = "(H (1 [50] 2 [25] 3))"
      End
      Begin PaneConfiguration = 3
         NumPanes = 3
         Configuration = "(H (4 [30] 2 [40] 3))"
      End
      Begin PaneConfiguration = 4
         NumPanes = 2
         Configuration = "(H (1 [56] 3))"
      End
      Begin PaneConfiguration = 5
         NumPanes = 2
         Configuration = "(H (2 [66] 3))"
      End
      Begin PaneConfiguration = 6
         NumPanes = 2
         Configuration = "(H (4 [50] 3))"
      End
      Begin PaneConfiguration = 7
         NumPanes = 1
         Configuration = "(V (3))"
      End
      Begin PaneConfiguration = 8
         NumPanes = 3
         Configuration = "(H (1[56] 4[18] 2) )"
      End
      Begin PaneConfiguration = 9
         NumPanes = 2
         Configuration = "(H (1 [75] 4))"
      End
      Begin PaneConfiguration = 10
         NumPanes = 2
         Configuration = "(H (1[66] 2) )"
      End
      Begin PaneConfiguration = 11
         NumPanes = 2
         Configuration = "(H (4 [60] 2))"
      End
      Begin PaneConfiguration = 12
         NumPanes = 1
         Configuration = "(H (1) )"
      End
      Begin PaneConfiguration = 13
         NumPanes = 1
         Configuration = "(V (4))"
      End
      Begin PaneConfiguration = 14
         NumPanes = 1
         Configuration = "(V (2))"
      End
      ActivePaneConfig = 0
   End
   Begin DiagramPane = 
      Begin Origin = 
         Top = 0
         Left = 0
      End
      Begin Tables = 
         Begin Table = "Product_BonusScheme"
            Begin Extent = 
               Top = 16
               Left = 49
               Bottom = 187
               Right = 219
            End
            DisplayFlags = 280
            TopColumn = 0
         End
         Begin Table = "Mx_BonusScheme"
            Begin Extent = 
               Top = 4
               Left = 366
               Bottom = 272
               Right = 536
            End
            DisplayFlags = 280
            TopColumn = 0
         End
      End
   End
   Begin SQLPane = 
   End
   Begin DataPane = 
      Begin ParameterDefaults = ""
      End
      Begin ColumnWidths = 9
         Width = 284
         Width = 1500
         Width = 1500
         Width = 1500
         Width = 1500
         Width = 1500
         Width = 1500
         Width = 1500
         Width = 1500
      End
   End
   Begin CriteriaPane = 
      Begin ColumnWidths = 11
         Column = 1440
         Alias = 900
         Table = 1170
         Output = 720
         Append = 1400
         NewValue = 1170
         SortType = 1350
         SortOrder = 1410
         GroupBy = 1350
         Filter = 1350
         Or = 1350
         Or = 1350
         Or = 1350
      End
   End
End
' , @level0type=N'SCHEMA',@level0name=N'dbo', @level1type=N'VIEW',@level1name=N'vw_Product_BonusScheme_Details'
GO
EXEC sys.sp_addextendedproperty @name=N'MS_DiagramPaneCount', @value=1 , @level0type=N'SCHEMA',@level0name=N'dbo', @level1type=N'VIEW',@level1name=N'vw_Product_BonusScheme_Details'
GO
EXEC sys.sp_addextendedproperty @name=N'MS_DiagramPane1', @value=N'[0E232FF0-B466-11cf-A24F-00AA00A3EFFF, 1.00]
Begin DesignProperties = 
   Begin PaneConfigurations = 
      Begin PaneConfiguration = 0
         NumPanes = 4
         Configuration = "(H (1[40] 4[20] 2[20] 3) )"
      End
      Begin PaneConfiguration = 1
         NumPanes = 3
         Configuration = "(H (1 [50] 4 [25] 3))"
      End
      Begin PaneConfiguration = 2
         NumPanes = 3
         Configuration = "(H (1 [50] 2 [25] 3))"
      End
      Begin PaneConfiguration = 3
         NumPanes = 3
         Configuration = "(H (4 [30] 2 [40] 3))"
      End
      Begin PaneConfiguration = 4
         NumPanes = 2
         Configuration = "(H (1 [56] 3))"
      End
      Begin PaneConfiguration = 5
         NumPanes = 2
         Configuration = "(H (2 [66] 3))"
      End
      Begin PaneConfiguration = 6
         NumPanes = 2
         Configuration = "(H (4 [50] 3))"
      End
      Begin PaneConfiguration = 7
         NumPanes = 1
         Configuration = "(V (3))"
      End
      Begin PaneConfiguration = 8
         NumPanes = 3
         Configuration = "(H (1[56] 4[18] 2) )"
      End
      Begin PaneConfiguration = 9
         NumPanes = 2
         Configuration = "(H (1 [75] 4))"
      End
      Begin PaneConfiguration = 10
         NumPanes = 2
         Configuration = "(H (1[66] 2) )"
      End
      Begin PaneConfiguration = 11
         NumPanes = 2
         Configuration = "(H (4 [60] 2))"
      End
      Begin PaneConfiguration = 12
         NumPanes = 1
         Configuration = "(H (1) )"
      End
      Begin PaneConfiguration = 13
         NumPanes = 1
         Configuration = "(V (4))"
      End
      Begin PaneConfiguration = 14
         NumPanes = 1
         Configuration = "(V (2))"
      End
      ActivePaneConfig = 0
   End
   Begin DiagramPane = 
      Begin Origin = 
         Top = 0
         Left = 0
      End
      Begin Tables = 
         Begin Table = "ProductSpecificUnitOfMeasureConversions"
            Begin Extent = 
               Top = 6
               Left = 38
               Bottom = 263
               Right = 217
            End
            DisplayFlags = 280
            TopColumn = 0
         End
      End
   End
   Begin SQLPane = 
   End
   Begin DataPane = 
      Begin ParameterDefaults = ""
      End
      Begin ColumnWidths = 9
         Width = 284
         Width = 1500
         Width = 1500
         Width = 1500
         Width = 1500
         Width = 1500
         Width = 1500
         Width = 1500
         Width = 1500
      End
   End
   Begin CriteriaPane = 
      Begin ColumnWidths = 12
         Column = 1440
         Alias = 900
         Table = 1170
         Output = 720
         Append = 1400
         NewValue = 1170
         SortType = 1350
         SortOrder = 1410
         GroupBy = 1350
         Filter = 1350
         Or = 1350
         Or = 1350
         Or = 1350
      End
   End
End
' , @level0type=N'SCHEMA',@level0name=N'dbo', @level1type=N'VIEW',@level1name=N'vw_ProductSpecificUnitOfMeasureConversions_pcs'
GO
EXEC sys.sp_addextendedproperty @name=N'MS_DiagramPaneCount', @value=1 , @level0type=N'SCHEMA',@level0name=N'dbo', @level1type=N'VIEW',@level1name=N'vw_ProductSpecificUnitOfMeasureConversions_pcs'
GO
EXEC sys.sp_addextendedproperty @name=N'MS_DiagramPane1', @value=N'[0E232FF0-B466-11cf-A24F-00AA00A3EFFF, 1.00]
Begin DesignProperties = 
   Begin PaneConfigurations = 
      Begin PaneConfiguration = 0
         NumPanes = 4
         Configuration = "(H (1[41] 4[14] 2[35] 3) )"
      End
      Begin PaneConfiguration = 1
         NumPanes = 3
         Configuration = "(H (1 [50] 4 [25] 3))"
      End
      Begin PaneConfiguration = 2
         NumPanes = 3
         Configuration = "(H (1 [50] 2 [25] 3))"
      End
      Begin PaneConfiguration = 3
         NumPanes = 3
         Configuration = "(H (4 [30] 2 [40] 3))"
      End
      Begin PaneConfiguration = 4
         NumPanes = 2
         Configuration = "(H (1 [56] 3))"
      End
      Begin PaneConfiguration = 5
         NumPanes = 2
         Configuration = "(H (2 [66] 3))"
      End
      Begin PaneConfiguration = 6
         NumPanes = 2
         Configuration = "(H (4 [50] 3))"
      End
      Begin PaneConfiguration = 7
         NumPanes = 1
         Configuration = "(V (3))"
      End
      Begin PaneConfiguration = 8
         NumPanes = 3
         Configuration = "(H (1[56] 4[18] 2) )"
      End
      Begin PaneConfiguration = 9
         NumPanes = 2
         Configuration = "(H (1 [75] 4))"
      End
      Begin PaneConfiguration = 10
         NumPanes = 2
         Configuration = "(H (1[66] 2) )"
      End
      Begin PaneConfiguration = 11
         NumPanes = 2
         Configuration = "(H (4 [60] 2))"
      End
      Begin PaneConfiguration = 12
         NumPanes = 1
         Configuration = "(H (1) )"
      End
      Begin PaneConfiguration = 13
         NumPanes = 1
         Configuration = "(V (4))"
      End
      Begin PaneConfiguration = 14
         NumPanes = 1
         Configuration = "(V (2))"
      End
      ActivePaneConfig = 0
   End
   Begin DiagramPane = 
      Begin Origin = 
         Top = 0
         Left = 0
      End
      Begin Tables = 
         Begin Table = "PurchaseOrderLinesV2"
            Begin Extent = 
               Top = 6
               Left = 38
               Bottom = 258
               Right = 354
            End
            DisplayFlags = 280
            TopColumn = 66
         End
         Begin Table = "PurchaseOrderHeadersV2"
            Begin Extent = 
               Top = 6
               Left = 1035
               Bottom = 298
               Right = 1353
            End
            DisplayFlags = 280
            TopColumn = 16
         End
         Begin Table = "ProductReceiptLines"
            Begin Extent = 
               Top = 16
               Left = 560
               Bottom = 264
               Right = 891
            End
            DisplayFlags = 280
            TopColumn = 2
         End
      End
   End
   Begin SQLPane = 
   End
   Begin DataPane = 
      Begin ParameterDefaults = ""
      End
      Begin ColumnWidths = 12
         Width = 284
         Width = 1500
         Width = 1500
         Width = 1500
         Width = 1500
         Width = 1500
         Width = 1500
         Width = 1500
         Width = 2025
         Width = 2805
         Width = 2940
         Width = 1500
      End
   End
   Begin CriteriaPane = 
      Begin ColumnWidths = 11
         Column = 7515
         Alias = 2880
         Table = 3405
         Output = 720
         Append = 1400
         NewValue = 1170
         SortType = 1350
         SortOrder = 1410
         GroupBy = 1350
         Filter = 1350
         Or = 1350
         Or = 1350
         Or = 1350
      End
   End
End
' , @level0type=N'SCHEMA',@level0name=N'dbo', @level1type=N'VIEW',@level1name=N'vw_PurchaseOrder_Status'
GO
EXEC sys.sp_addextendedproperty @name=N'MS_DiagramPaneCount', @value=1 , @level0type=N'SCHEMA',@level0name=N'dbo', @level1type=N'VIEW',@level1name=N'vw_PurchaseOrder_Status'
GO
EXEC sys.sp_addextendedproperty @name=N'MS_DiagramPane1', @value=N'[0E232FF0-B466-11cf-A24F-00AA00A3EFFF, 1.00]
Begin DesignProperties = 
   Begin PaneConfigurations = 
      Begin PaneConfiguration = 0
         NumPanes = 4
         Configuration = "(H (1[39] 4[23] 2[17] 3) )"
      End
      Begin PaneConfiguration = 1
         NumPanes = 3
         Configuration = "(H (1 [50] 4 [25] 3))"
      End
      Begin PaneConfiguration = 2
         NumPanes = 3
         Configuration = "(H (1 [50] 2 [25] 3))"
      End
      Begin PaneConfiguration = 3
         NumPanes = 3
         Configuration = "(H (4 [30] 2 [40] 3))"
      End
      Begin PaneConfiguration = 4
         NumPanes = 2
         Configuration = "(H (1 [56] 3))"
      End
      Begin PaneConfiguration = 5
         NumPanes = 2
         Configuration = "(H (2 [66] 3))"
      End
      Begin PaneConfiguration = 6
         NumPanes = 2
         Configuration = "(H (4 [50] 3))"
      End
      Begin PaneConfiguration = 7
         NumPanes = 1
         Configuration = "(V (3))"
      End
      Begin PaneConfiguration = 8
         NumPanes = 3
         Configuration = "(H (1[56] 4[18] 2) )"
      End
      Begin PaneConfiguration = 9
         NumPanes = 2
         Configuration = "(H (1 [75] 4))"
      End
      Begin PaneConfiguration = 10
         NumPanes = 2
         Configuration = "(H (1[66] 2) )"
      End
      Begin PaneConfiguration = 11
         NumPanes = 2
         Configuration = "(H (4 [60] 2))"
      End
      Begin PaneConfiguration = 12
         NumPanes = 1
         Configuration = "(H (1) )"
      End
      Begin PaneConfiguration = 13
         NumPanes = 1
         Configuration = "(V (4))"
      End
      Begin PaneConfiguration = 14
         NumPanes = 1
         Configuration = "(V (2))"
      End
      ActivePaneConfig = 0
   End
   Begin DiagramPane = 
      Begin Origin = 
         Top = 0
         Left = 0
      End
      Begin Tables = 
         Begin Table = "PurchaseOrderConfirmationLines"
            Begin Extent = 
               Top = 0
               Left = 215
               Bottom = 303
               Right = 514
            End
            DisplayFlags = 280
            TopColumn = 2
         End
         Begin Table = "PurchaseOrderConfirmationLines_1"
            Begin Extent = 
               Top = 0
               Left = 626
               Bottom = 304
               Right = 994
            End
            DisplayFlags = 280
            TopColumn = 0
         End
      End
   End
   Begin SQLPane = 
   End
   Begin DataPane = 
      Begin ParameterDefaults = ""
      End
      Begin ColumnWidths = 9
         Width = 284
         Width = 1500
         Width = 1500
         Width = 1500
         Width = 1500
         Width = 1500
         Width = 1500
         Width = 1500
         Width = 1500
      End
   End
   Begin CriteriaPane = 
      Begin ColumnWidths = 12
         Column = 3645
         Alias = 900
         Table = 3750
         Output = 720
         Append = 1400
         NewValue = 1170
         SortType = 1350
         SortOrder = 1410
         GroupBy = 1350
         Filter = 1350
         Or = 1350
         Or = 1350
         Or = 1350
      End
   End
End
' , @level0type=N'SCHEMA',@level0name=N'dbo', @level1type=N'VIEW',@level1name=N'vw_PurchaseOrderConfirmationLines_Ordered_Delivered'
GO
EXEC sys.sp_addextendedproperty @name=N'MS_DiagramPaneCount', @value=1 , @level0type=N'SCHEMA',@level0name=N'dbo', @level1type=N'VIEW',@level1name=N'vw_PurchaseOrderConfirmationLines_Ordered_Delivered'
GO
EXEC sys.sp_addextendedproperty @name=N'MS_DiagramPane1', @value=N'[0E232FF0-B466-11cf-A24F-00AA00A3EFFF, 1.00]
Begin DesignProperties = 
   Begin PaneConfigurations = 
      Begin PaneConfiguration = 0
         NumPanes = 4
         Configuration = "(H (1[40] 4[28] 2[14] 3) )"
      End
      Begin PaneConfiguration = 1
         NumPanes = 3
         Configuration = "(H (1 [50] 4 [25] 3))"
      End
      Begin PaneConfiguration = 2
         NumPanes = 3
         Configuration = "(H (1 [50] 2 [25] 3))"
      End
      Begin PaneConfiguration = 3
         NumPanes = 3
         Configuration = "(H (4 [30] 2 [40] 3))"
      End
      Begin PaneConfiguration = 4
         NumPanes = 2
         Configuration = "(H (1 [56] 3))"
      End
      Begin PaneConfiguration = 5
         NumPanes = 2
         Configuration = "(H (2 [66] 3))"
      End
      Begin PaneConfiguration = 6
         NumPanes = 2
         Configuration = "(H (4 [50] 3))"
      End
      Begin PaneConfiguration = 7
         NumPanes = 1
         Configuration = "(V (3))"
      End
      Begin PaneConfiguration = 8
         NumPanes = 3
         Configuration = "(H (1[56] 4[18] 2) )"
      End
      Begin PaneConfiguration = 9
         NumPanes = 2
         Configuration = "(H (1 [75] 4))"
      End
      Begin PaneConfiguration = 10
         NumPanes = 2
         Configuration = "(H (1[66] 2) )"
      End
      Begin PaneConfiguration = 11
         NumPanes = 2
         Configuration = "(H (4 [60] 2))"
      End
      Begin PaneConfiguration = 12
         NumPanes = 1
         Configuration = "(H (1) )"
      End
      Begin PaneConfiguration = 13
         NumPanes = 1
         Configuration = "(V (4))"
      End
      Begin PaneConfiguration = 14
         NumPanes = 1
         Configuration = "(V (2))"
      End
      ActivePaneConfig = 0
   End
   Begin DiagramPane = 
      Begin Origin = 
         Top = 0
         Left = 0
      End
      Begin Tables = 
         Begin Table = "ReleasedProductCreationsV2"
            Begin Extent = 
               Top = 6
               Left = 38
               Bottom = 296
               Right = 350
            End
            DisplayFlags = 280
            TopColumn = 0
         End
         Begin Table = "vw_ProductSpecificUnitOfMeasureConversions_pcs"
            Begin Extent = 
               Top = 218
               Left = 472
               Bottom = 314
               Right = 647
            End
            DisplayFlags = 280
            TopColumn = 0
         End
         Begin Table = "VendorProductDescriptionsV2"
            Begin Extent = 
               Top = 224
               Left = 768
               Bottom = 320
               Right = 1083
            End
            DisplayFlags = 280
            TopColumn = 0
         End
         Begin Table = "items_d365"
            Begin Extent = 
               Top = 13
               Left = 524
               Bottom = 168
               Right = 694
            End
            DisplayFlags = 280
            TopColumn = 0
         End
      End
   End
   Begin SQLPane = 
   End
   Begin DataPane = 
      Begin ParameterDefaults = ""
      End
      Begin ColumnWidths = 14
         Width = 284
         Width = 1500
         Width = 1500
         Width = 1500
         Width = 1500
         Width = 1500
         Width = 1500
         Width = 1500
         Width = 1500
         Width = 1500
         Width = 1500
         Width = 1500
         Width = 1500
         Width = 1500
      End
   End
   Begin CriteriaPane = 
      Begin ColumnWidths = 11
         Column = 3645
         Alias = 900
         Table = 1170
         Output = 720
         Append = 1400
 ' , @level0type=N'SCHEMA',@level0name=N'dbo', @level1type=N'VIEW',@level1name=N'vw_ReleasedProductCreationsV2'
GO
EXEC sys.sp_addextendedproperty @name=N'MS_DiagramPane2', @value=N'        NewValue = 1170
         SortType = 1350
         SortOrder = 1410
         GroupBy = 1350
         Filter = 1350
         Or = 1350
         Or = 1350
         Or = 1350
      End
   End
End
' , @level0type=N'SCHEMA',@level0name=N'dbo', @level1type=N'VIEW',@level1name=N'vw_ReleasedProductCreationsV2'
GO
EXEC sys.sp_addextendedproperty @name=N'MS_DiagramPaneCount', @value=2 , @level0type=N'SCHEMA',@level0name=N'dbo', @level1type=N'VIEW',@level1name=N'vw_ReleasedProductCreationsV2'
GO
EXEC sys.sp_addextendedproperty @name=N'MS_DiagramPane1', @value=N'[0E232FF0-B466-11cf-A24F-00AA00A3EFFF, 1.00]
Begin DesignProperties = 
   Begin PaneConfigurations = 
      Begin PaneConfiguration = 0
         NumPanes = 4
         Configuration = "(H (1[40] 4[20] 2[20] 3) )"
      End
      Begin PaneConfiguration = 1
         NumPanes = 3
         Configuration = "(H (1 [50] 4 [25] 3))"
      End
      Begin PaneConfiguration = 2
         NumPanes = 3
         Configuration = "(H (1 [50] 2 [25] 3))"
      End
      Begin PaneConfiguration = 3
         NumPanes = 3
         Configuration = "(H (4 [30] 2 [40] 3))"
      End
      Begin PaneConfiguration = 4
         NumPanes = 2
         Configuration = "(H (1 [56] 3))"
      End
      Begin PaneConfiguration = 5
         NumPanes = 2
         Configuration = "(H (2 [66] 3))"
      End
      Begin PaneConfiguration = 6
         NumPanes = 2
         Configuration = "(H (4 [50] 3))"
      End
      Begin PaneConfiguration = 7
         NumPanes = 1
         Configuration = "(V (3))"
      End
      Begin PaneConfiguration = 8
         NumPanes = 3
         Configuration = "(H (1[56] 4[18] 2) )"
      End
      Begin PaneConfiguration = 9
         NumPanes = 2
         Configuration = "(H (1 [75] 4))"
      End
      Begin PaneConfiguration = 10
         NumPanes = 2
         Configuration = "(H (1[66] 2) )"
      End
      Begin PaneConfiguration = 11
         NumPanes = 2
         Configuration = "(H (4 [60] 2))"
      End
      Begin PaneConfiguration = 12
         NumPanes = 1
         Configuration = "(H (1) )"
      End
      Begin PaneConfiguration = 13
         NumPanes = 1
         Configuration = "(V (4))"
      End
      Begin PaneConfiguration = 14
         NumPanes = 1
         Configuration = "(V (2))"
      End
      ActivePaneConfig = 0
   End
   Begin DiagramPane = 
      Begin Origin = 
         Top = 0
         Left = 0
      End
      Begin Tables = 
         Begin Table = "ReleasedProductCreationsV2_auto"
            Begin Extent = 
               Top = 6
               Left = 38
               Bottom = 136
               Right = 304
            End
            DisplayFlags = 280
            TopColumn = 0
         End
         Begin Table = "vw_ProductSpecificUnitOfMeasureConversions_pcs"
            Begin Extent = 
               Top = 138
               Left = 38
               Bottom = 234
               Right = 213
            End
            DisplayFlags = 280
            TopColumn = 0
         End
         Begin Table = "VendorProductDescriptionsV2"
            Begin Extent = 
               Top = 138
               Left = 251
               Bottom = 234
               Right = 464
            End
            DisplayFlags = 280
            TopColumn = 0
         End
         Begin Table = "items_d365"
            Begin Extent = 
               Top = 234
               Left = 38
               Bottom = 347
               Right = 208
            End
            DisplayFlags = 280
            TopColumn = 0
         End
      End
   End
   Begin SQLPane = 
   End
   Begin DataPane = 
      Begin ParameterDefaults = ""
      End
      Begin ColumnWidths = 10
         Width = 284
         Width = 1500
         Width = 1500
         Width = 1500
         Width = 1500
         Width = 1500
         Width = 1500
         Width = 1500
         Width = 1500
         Width = 1500
      End
   End
   Begin CriteriaPane = 
      Begin ColumnWidths = 11
         Column = 1440
         Alias = 900
         Table = 1170
         Output = 720
         Append = 1400
         NewValue = 1170
         SortType = 1350
         SortOrder = 1410
         Gr' , @level0type=N'SCHEMA',@level0name=N'dbo', @level1type=N'VIEW',@level1name=N'vw_ReleasedProductCreationsV2_auto'
GO
EXEC sys.sp_addextendedproperty @name=N'MS_DiagramPane2', @value=N'oupBy = 1350
         Filter = 1350
         Or = 1350
         Or = 1350
         Or = 1350
      End
   End
End
' , @level0type=N'SCHEMA',@level0name=N'dbo', @level1type=N'VIEW',@level1name=N'vw_ReleasedProductCreationsV2_auto'
GO
EXEC sys.sp_addextendedproperty @name=N'MS_DiagramPaneCount', @value=2 , @level0type=N'SCHEMA',@level0name=N'dbo', @level1type=N'VIEW',@level1name=N'vw_ReleasedProductCreationsV2_auto'
GO
EXEC sys.sp_addextendedproperty @name=N'MS_DiagramPane1', @value=N'[0E232FF0-B466-11cf-A24F-00AA00A3EFFF, 1.00]
Begin DesignProperties = 
   Begin PaneConfigurations = 
      Begin PaneConfiguration = 0
         NumPanes = 4
         Configuration = "(H (1[47] 4[15] 2[20] 3) )"
      End
      Begin PaneConfiguration = 1
         NumPanes = 3
         Configuration = "(H (1 [50] 4 [25] 3))"
      End
      Begin PaneConfiguration = 2
         NumPanes = 3
         Configuration = "(H (1 [50] 2 [25] 3))"
      End
      Begin PaneConfiguration = 3
         NumPanes = 3
         Configuration = "(H (4 [30] 2 [40] 3))"
      End
      Begin PaneConfiguration = 4
         NumPanes = 2
         Configuration = "(H (1 [56] 3))"
      End
      Begin PaneConfiguration = 5
         NumPanes = 2
         Configuration = "(H (2 [66] 3))"
      End
      Begin PaneConfiguration = 6
         NumPanes = 2
         Configuration = "(H (4 [50] 3))"
      End
      Begin PaneConfiguration = 7
         NumPanes = 1
         Configuration = "(V (3))"
      End
      Begin PaneConfiguration = 8
         NumPanes = 3
         Configuration = "(H (1[56] 4[18] 2) )"
      End
      Begin PaneConfiguration = 9
         NumPanes = 2
         Configuration = "(H (1 [75] 4))"
      End
      Begin PaneConfiguration = 10
         NumPanes = 2
         Configuration = "(H (1[66] 2) )"
      End
      Begin PaneConfiguration = 11
         NumPanes = 2
         Configuration = "(H (4 [60] 2))"
      End
      Begin PaneConfiguration = 12
         NumPanes = 1
         Configuration = "(H (1) )"
      End
      Begin PaneConfiguration = 13
         NumPanes = 1
         Configuration = "(V (4))"
      End
      Begin PaneConfiguration = 14
         NumPanes = 1
         Configuration = "(V (2))"
      End
      ActivePaneConfig = 0
   End
   Begin DiagramPane = 
      Begin Origin = 
         Top = 0
         Left = 0
      End
      Begin Tables = 
         Begin Table = "D365_Sales_Registers_from_PBi"
            Begin Extent = 
               Top = 6
               Left = 38
               Bottom = 136
               Right = 253
            End
            DisplayFlags = 280
            TopColumn = 26
         End
         Begin Table = "Mx_Preferred_List"
            Begin Extent = 
               Top = 232
               Left = 551
               Bottom = 362
               Right = 721
            End
            DisplayFlags = 280
            TopColumn = 0
         End
         Begin Table = "Workers"
            Begin Extent = 
               Top = 5
               Left = 306
               Bottom = 135
               Right = 491
            End
            DisplayFlags = 280
            TopColumn = 0
         End
         Begin Table = "ProductCategoryAssignments_1"
            Begin Extent = 
               Top = 7
               Left = 523
               Bottom = 137
               Right = 785
            End
            DisplayFlags = 280
            TopColumn = 0
         End
         Begin Table = "ProductCategoryAssignments"
            Begin Extent = 
               Top = 6
               Left = 838
               Bottom = 136
               Right = 1100
            End
            DisplayFlags = 280
            TopColumn = 0
         End
      End
   End
   Begin SQLPane = 
   End
   Begin DataPane = 
      Begin ParameterDefaults = ""
      End
      Begin ColumnWidths = 24
         Width = 284
         Width = 1500
         Width = 1500
         Width = 1500
         Width = 1500
         Width = 1500
         Width = 1500
         Width = 1500
         Width = 1500
         Width = 1500
         Width = 1500
         Wid' , @level0type=N'SCHEMA',@level0name=N'dbo', @level1type=N'VIEW',@level1name=N'vw_Sales_Registers_Portal'
GO
EXEC sys.sp_addextendedproperty @name=N'MS_DiagramPane2', @value=N'th = 1500
         Width = 1500
         Width = 1500
         Width = 1500
         Width = 1500
         Width = 1500
         Width = 1500
         Width = 1500
         Width = 1500
         Width = 1500
         Width = 1500
         Width = 1500
         Width = 1500
      End
   End
   Begin CriteriaPane = 
      Begin ColumnWidths = 11
         Column = 12675
         Alias = 900
         Table = 1170
         Output = 720
         Append = 1400
         NewValue = 1170
         SortType = 1350
         SortOrder = 1410
         GroupBy = 1350
         Filter = 1350
         Or = 1350
         Or = 1350
         Or = 1350
      End
   End
End
' , @level0type=N'SCHEMA',@level0name=N'dbo', @level1type=N'VIEW',@level1name=N'vw_Sales_Registers_Portal'
GO
EXEC sys.sp_addextendedproperty @name=N'MS_DiagramPaneCount', @value=2 , @level0type=N'SCHEMA',@level0name=N'dbo', @level1type=N'VIEW',@level1name=N'vw_Sales_Registers_Portal'
GO
EXEC sys.sp_addextendedproperty @name=N'MS_DiagramPane1', @value=N'[0E232FF0-B466-11cf-A24F-00AA00A3EFFF, 1.00]
Begin DesignProperties = 
   Begin PaneConfigurations = 
      Begin PaneConfiguration = 0
         NumPanes = 4
         Configuration = "(H (1[40] 4[20] 2[20] 3) )"
      End
      Begin PaneConfiguration = 1
         NumPanes = 3
         Configuration = "(H (1 [50] 4 [25] 3))"
      End
      Begin PaneConfiguration = 2
         NumPanes = 3
         Configuration = "(H (1 [50] 2 [25] 3))"
      End
      Begin PaneConfiguration = 3
         NumPanes = 3
         Configuration = "(H (4 [30] 2 [40] 3))"
      End
      Begin PaneConfiguration = 4
         NumPanes = 2
         Configuration = "(H (1 [56] 3))"
      End
      Begin PaneConfiguration = 5
         NumPanes = 2
         Configuration = "(H (2 [66] 3))"
      End
      Begin PaneConfiguration = 6
         NumPanes = 2
         Configuration = "(H (4 [50] 3))"
      End
      Begin PaneConfiguration = 7
         NumPanes = 1
         Configuration = "(V (3))"
      End
      Begin PaneConfiguration = 8
         NumPanes = 3
         Configuration = "(H (1[56] 4[18] 2) )"
      End
      Begin PaneConfiguration = 9
         NumPanes = 2
         Configuration = "(H (1 [75] 4))"
      End
      Begin PaneConfiguration = 10
         NumPanes = 2
         Configuration = "(H (1[66] 2) )"
      End
      Begin PaneConfiguration = 11
         NumPanes = 2
         Configuration = "(H (4 [60] 2))"
      End
      Begin PaneConfiguration = 12
         NumPanes = 1
         Configuration = "(H (1) )"
      End
      Begin PaneConfiguration = 13
         NumPanes = 1
         Configuration = "(V (4))"
      End
      Begin PaneConfiguration = 14
         NumPanes = 1
         Configuration = "(V (2))"
      End
      ActivePaneConfig = 0
   End
   Begin DiagramPane = 
      Begin Origin = 
         Top = 0
         Left = 0
      End
      Begin Tables = 
         Begin Table = "D365_Sales_Registers_from_PBi"
            Begin Extent = 
               Top = 6
               Left = 38
               Bottom = 308
               Right = 253
            End
            DisplayFlags = 280
            TopColumn = 20
         End
         Begin Table = "ProductCategoryAssignments"
            Begin Extent = 
               Top = 6
               Left = 291
               Bottom = 136
               Right = 553
            End
            DisplayFlags = 280
            TopColumn = 0
         End
         Begin Table = "ProductCategoryAssignments_1"
            Begin Extent = 
               Top = 176
               Left = 454
               Bottom = 318
               Right = 729
            End
            DisplayFlags = 280
            TopColumn = 0
         End
         Begin Table = "Workers"
            Begin Extent = 
               Top = 71
               Left = 792
               Bottom = 307
               Right = 1118
            End
            DisplayFlags = 280
            TopColumn = 21
         End
      End
   End
   Begin SQLPane = 
   End
   Begin DataPane = 
      Begin ParameterDefaults = ""
      End
      Begin ColumnWidths = 9
         Width = 284
         Width = 1500
         Width = 1500
         Width = 1500
         Width = 1500
         Width = 1500
         Width = 1500
         Width = 1500
         Width = 1500
      End
   End
   Begin CriteriaPane = 
      Begin ColumnWidths = 11
         Column = 1440
         Alias = 900
         Table = 1170
         Output = 720
         Append = 1400
         NewValue = 1170
         SortType = 1350
         SortOrder = 1410
         GroupBy = 1350
         Filter = 1350
        ' , @level0type=N'SCHEMA',@level0name=N'dbo', @level1type=N'VIEW',@level1name=N'vw_Sales_Registers+'
GO
EXEC sys.sp_addextendedproperty @name=N'MS_DiagramPane2', @value=N' Or = 1350
         Or = 1350
         Or = 1350
      End
   End
End
' , @level0type=N'SCHEMA',@level0name=N'dbo', @level1type=N'VIEW',@level1name=N'vw_Sales_Registers+'
GO
EXEC sys.sp_addextendedproperty @name=N'MS_DiagramPaneCount', @value=2 , @level0type=N'SCHEMA',@level0name=N'dbo', @level1type=N'VIEW',@level1name=N'vw_Sales_Registers+'
GO
EXEC sys.sp_addextendedproperty @name=N'MS_DiagramPane1', @value=N'[0E232FF0-B466-11cf-A24F-00AA00A3EFFF, 1.00]
Begin DesignProperties = 
   Begin PaneConfigurations = 
      Begin PaneConfiguration = 0
         NumPanes = 4
         Configuration = "(H (1[41] 4[20] 2[13] 3) )"
      End
      Begin PaneConfiguration = 1
         NumPanes = 3
         Configuration = "(H (1 [50] 4 [25] 3))"
      End
      Begin PaneConfiguration = 2
         NumPanes = 3
         Configuration = "(H (1 [50] 2 [25] 3))"
      End
      Begin PaneConfiguration = 3
         NumPanes = 3
         Configuration = "(H (4 [30] 2 [40] 3))"
      End
      Begin PaneConfiguration = 4
         NumPanes = 2
         Configuration = "(H (1 [56] 3))"
      End
      Begin PaneConfiguration = 5
         NumPanes = 2
         Configuration = "(H (2 [66] 3))"
      End
      Begin PaneConfiguration = 6
         NumPanes = 2
         Configuration = "(H (4 [50] 3))"
      End
      Begin PaneConfiguration = 7
         NumPanes = 1
         Configuration = "(V (3))"
      End
      Begin PaneConfiguration = 8
         NumPanes = 3
         Configuration = "(H (1[56] 4[18] 2) )"
      End
      Begin PaneConfiguration = 9
         NumPanes = 2
         Configuration = "(H (1 [75] 4))"
      End
      Begin PaneConfiguration = 10
         NumPanes = 2
         Configuration = "(H (1[66] 2) )"
      End
      Begin PaneConfiguration = 11
         NumPanes = 2
         Configuration = "(H (4 [60] 2))"
      End
      Begin PaneConfiguration = 12
         NumPanes = 1
         Configuration = "(H (1) )"
      End
      Begin PaneConfiguration = 13
         NumPanes = 1
         Configuration = "(V (4))"
      End
      Begin PaneConfiguration = 14
         NumPanes = 1
         Configuration = "(V (2))"
      End
      ActivePaneConfig = 0
   End
   Begin DiagramPane = 
      Begin Origin = 
         Top = 0
         Left = 0
      End
      Begin Tables = 
         Begin Table = "TransferOrderHeaders"
            Begin Extent = 
               Top = 6
               Left = 38
               Bottom = 259
               Right = 253
            End
            DisplayFlags = 280
            TopColumn = 0
         End
         Begin Table = "TransferOrderLines"
            Begin Extent = 
               Top = 27
               Left = 423
               Bottom = 313
               Right = 795
            End
            DisplayFlags = 280
            TopColumn = 0
         End
      End
   End
   Begin SQLPane = 
   End
   Begin DataPane = 
      Begin ParameterDefaults = ""
      End
      Begin ColumnWidths = 9
         Width = 284
         Width = 1500
         Width = 1500
         Width = 1500
         Width = 1500
         Width = 1500
         Width = 1500
         Width = 1500
         Width = 1500
      End
   End
   Begin CriteriaPane = 
      Begin ColumnWidths = 12
         Column = 3855
         Alias = 900
         Table = 1170
         Output = 720
         Append = 1400
         NewValue = 1170
         SortType = 1350
         SortOrder = 1410
         GroupBy = 1350
         Filter = 5865
         Or = 1350
         Or = 1350
         Or = 1350
      End
   End
End
' , @level0type=N'SCHEMA',@level0name=N'dbo', @level1type=N'VIEW',@level1name=N'vw_TransferOrder_Pending_Sum'
GO
EXEC sys.sp_addextendedproperty @name=N'MS_DiagramPaneCount', @value=1 , @level0type=N'SCHEMA',@level0name=N'dbo', @level1type=N'VIEW',@level1name=N'vw_TransferOrder_Pending_Sum'
GO
EXEC sys.sp_addextendedproperty @name=N'MS_DiagramPane1', @value=N'[0E232FF0-B466-11cf-A24F-00AA00A3EFFF, 1.00]
Begin DesignProperties = 
   Begin PaneConfigurations = 
      Begin PaneConfiguration = 0
         NumPanes = 4
         Configuration = "(H (1[40] 4[20] 2[20] 3) )"
      End
      Begin PaneConfiguration = 1
         NumPanes = 3
         Configuration = "(H (1 [50] 4 [25] 3))"
      End
      Begin PaneConfiguration = 2
         NumPanes = 3
         Configuration = "(H (1 [50] 2 [25] 3))"
      End
      Begin PaneConfiguration = 3
         NumPanes = 3
         Configuration = "(H (4 [30] 2 [40] 3))"
      End
      Begin PaneConfiguration = 4
         NumPanes = 2
         Configuration = "(H (1 [56] 3))"
      End
      Begin PaneConfiguration = 5
         NumPanes = 2
         Configuration = "(H (2 [66] 3))"
      End
      Begin PaneConfiguration = 6
         NumPanes = 2
         Configuration = "(H (4 [50] 3))"
      End
      Begin PaneConfiguration = 7
         NumPanes = 1
         Configuration = "(V (3))"
      End
      Begin PaneConfiguration = 8
         NumPanes = 3
         Configuration = "(H (1[56] 4[18] 2) )"
      End
      Begin PaneConfiguration = 9
         NumPanes = 2
         Configuration = "(H (1 [75] 4))"
      End
      Begin PaneConfiguration = 10
         NumPanes = 2
         Configuration = "(H (1[66] 2) )"
      End
      Begin PaneConfiguration = 11
         NumPanes = 2
         Configuration = "(H (4 [60] 2))"
      End
      Begin PaneConfiguration = 12
         NumPanes = 1
         Configuration = "(H (1) )"
      End
      Begin PaneConfiguration = 13
         NumPanes = 1
         Configuration = "(V (4))"
      End
      Begin PaneConfiguration = 14
         NumPanes = 1
         Configuration = "(V (2))"
      End
      ActivePaneConfig = 0
   End
   Begin DiagramPane = 
      Begin Origin = 
         Top = 0
         Left = 0
      End
      Begin Tables = 
         Begin Table = "TransferOrderHeaders"
            Begin Extent = 
               Top = 6
               Left = 38
               Bottom = 260
               Right = 315
            End
            DisplayFlags = 280
            TopColumn = 0
         End
         Begin Table = "TransferOrderLines"
            Begin Extent = 
               Top = 36
               Left = 502
               Bottom = 293
               Right = 921
            End
            DisplayFlags = 280
            TopColumn = 0
         End
      End
   End
   Begin SQLPane = 
   End
   Begin DataPane = 
      Begin ParameterDefaults = ""
      End
   End
   Begin CriteriaPane = 
      Begin ColumnWidths = 12
         Column = 2580
         Alias = 900
         Table = 1170
         Output = 720
         Append = 1400
         NewValue = 1170
         SortType = 1350
         SortOrder = 1410
         GroupBy = 1350
         Filter = 4290
         Or = 1350
         Or = 1350
         Or = 1350
      End
   End
End
' , @level0type=N'SCHEMA',@level0name=N'dbo', @level1type=N'VIEW',@level1name=N'vw_TransferOrder_Pending_Sum_BR2WH'
GO
EXEC sys.sp_addextendedproperty @name=N'MS_DiagramPaneCount', @value=1 , @level0type=N'SCHEMA',@level0name=N'dbo', @level1type=N'VIEW',@level1name=N'vw_TransferOrder_Pending_Sum_BR2WH'
GO
EXEC sys.sp_addextendedproperty @name=N'MS_DiagramPane1', @value=N'[0E232FF0-B466-11cf-A24F-00AA00A3EFFF, 1.00]
Begin DesignProperties = 
   Begin PaneConfigurations = 
      Begin PaneConfiguration = 0
         NumPanes = 4
         Configuration = "(H (1[40] 4[20] 2[20] 3) )"
      End
      Begin PaneConfiguration = 1
         NumPanes = 3
         Configuration = "(H (1 [50] 4 [25] 3))"
      End
      Begin PaneConfiguration = 2
         NumPanes = 3
         Configuration = "(H (1 [50] 2 [25] 3))"
      End
      Begin PaneConfiguration = 3
         NumPanes = 3
         Configuration = "(H (4 [30] 2 [40] 3))"
      End
      Begin PaneConfiguration = 4
         NumPanes = 2
         Configuration = "(H (1 [56] 3))"
      End
      Begin PaneConfiguration = 5
         NumPanes = 2
         Configuration = "(H (2 [66] 3))"
      End
      Begin PaneConfiguration = 6
         NumPanes = 2
         Configuration = "(H (4 [50] 3))"
      End
      Begin PaneConfiguration = 7
         NumPanes = 1
         Configuration = "(V (3))"
      End
      Begin PaneConfiguration = 8
         NumPanes = 3
         Configuration = "(H (1[56] 4[18] 2) )"
      End
      Begin PaneConfiguration = 9
         NumPanes = 2
         Configuration = "(H (1 [75] 4))"
      End
      Begin PaneConfiguration = 10
         NumPanes = 2
         Configuration = "(H (1[66] 2) )"
      End
      Begin PaneConfiguration = 11
         NumPanes = 2
         Configuration = "(H (4 [60] 2))"
      End
      Begin PaneConfiguration = 12
         NumPanes = 1
         Configuration = "(H (1) )"
      End
      Begin PaneConfiguration = 13
         NumPanes = 1
         Configuration = "(V (4))"
      End
      Begin PaneConfiguration = 14
         NumPanes = 1
         Configuration = "(V (2))"
      End
      ActivePaneConfig = 0
   End
   Begin DiagramPane = 
      Begin Origin = 
         Top = 0
         Left = 0
      End
      Begin Tables = 
         Begin Table = "TransferOrderHeaders"
            Begin Extent = 
               Top = 6
               Left = 38
               Bottom = 262
               Right = 253
            End
            DisplayFlags = 280
            TopColumn = 0
         End
      End
   End
   Begin SQLPane = 
   End
   Begin DataPane = 
      Begin ParameterDefaults = ""
      End
      Begin ColumnWidths = 9
         Width = 284
         Width = 1500
         Width = 1500
         Width = 1500
         Width = 1500
         Width = 1500
         Width = 1500
         Width = 1500
         Width = 1500
      End
   End
   Begin CriteriaPane = 
      Begin ColumnWidths = 11
         Column = 2970
         Alias = 900
         Table = 1170
         Output = 720
         Append = 1400
         NewValue = 1170
         SortType = 1350
         SortOrder = 1410
         GroupBy = 1350
         Filter = 1710
         Or = 1350
         Or = 1350
         Or = 1350
      End
   End
End
' , @level0type=N'SCHEMA',@level0name=N'dbo', @level1type=N'VIEW',@level1name=N'vw_TransferOrderHeaders_Pending'
GO
EXEC sys.sp_addextendedproperty @name=N'MS_DiagramPaneCount', @value=1 , @level0type=N'SCHEMA',@level0name=N'dbo', @level1type=N'VIEW',@level1name=N'vw_TransferOrderHeaders_Pending'
GO
EXEC sys.sp_addextendedproperty @name=N'MS_DiagramPane1', @value=N'[0E232FF0-B466-11cf-A24F-00AA00A3EFFF, 1.00]
Begin DesignProperties = 
   Begin PaneConfigurations = 
      Begin PaneConfiguration = 0
         NumPanes = 4
         Configuration = "(H (1[40] 4[20] 2[20] 3) )"
      End
      Begin PaneConfiguration = 1
         NumPanes = 3
         Configuration = "(H (1 [50] 4 [25] 3))"
      End
      Begin PaneConfiguration = 2
         NumPanes = 3
         Configuration = "(H (1 [50] 2 [25] 3))"
      End
      Begin PaneConfiguration = 3
         NumPanes = 3
         Configuration = "(H (4 [30] 2 [40] 3))"
      End
      Begin PaneConfiguration = 4
         NumPanes = 2
         Configuration = "(H (1 [56] 3))"
      End
      Begin PaneConfiguration = 5
         NumPanes = 2
         Configuration = "(H (2 [66] 3))"
      End
      Begin PaneConfiguration = 6
         NumPanes = 2
         Configuration = "(H (4 [50] 3))"
      End
      Begin PaneConfiguration = 7
         NumPanes = 1
         Configuration = "(V (3))"
      End
      Begin PaneConfiguration = 8
         NumPanes = 3
         Configuration = "(H (1[56] 4[18] 2) )"
      End
      Begin PaneConfiguration = 9
         NumPanes = 2
         Configuration = "(H (1 [75] 4))"
      End
      Begin PaneConfiguration = 10
         NumPanes = 2
         Configuration = "(H (1[66] 2) )"
      End
      Begin PaneConfiguration = 11
         NumPanes = 2
         Configuration = "(H (4 [60] 2))"
      End
      Begin PaneConfiguration = 12
         NumPanes = 1
         Configuration = "(H (1) )"
      End
      Begin PaneConfiguration = 13
         NumPanes = 1
         Configuration = "(V (4))"
      End
      Begin PaneConfiguration = 14
         NumPanes = 1
         Configuration = "(V (2))"
      End
      ActivePaneConfig = 0
   End
   Begin DiagramPane = 
      Begin Origin = 
         Top = 0
         Left = 0
      End
      Begin Tables = 
         Begin Table = "TransferOrderLines"
            Begin Extent = 
               Top = 6
               Left = 38
               Bottom = 136
               Right = 290
            End
            DisplayFlags = 280
            TopColumn = 0
         End
         Begin Table = "TransferOrderHeaders"
            Begin Extent = 
               Top = 32
               Left = 411
               Bottom = 162
               Right = 626
            End
            DisplayFlags = 280
            TopColumn = 4
         End
      End
   End
   Begin SQLPane = 
   End
   Begin DataPane = 
      Begin ParameterDefaults = ""
      End
      Begin ColumnWidths = 9
         Width = 284
         Width = 1500
         Width = 1500
         Width = 1500
         Width = 1500
         Width = 1500
         Width = 1500
         Width = 1500
         Width = 1500
      End
   End
   Begin CriteriaPane = 
      Begin ColumnWidths = 11
         Column = 1440
         Alias = 900
         Table = 1170
         Output = 720
         Append = 1400
         NewValue = 1170
         SortType = 1350
         SortOrder = 1410
         GroupBy = 1350
         Filter = 1350
         Or = 1350
         Or = 1350
         Or = 1350
      End
   End
End
' , @level0type=N'SCHEMA',@level0name=N'dbo', @level1type=N'VIEW',@level1name=N'vw_TransferOrderLines_Pending_ALL'
GO
EXEC sys.sp_addextendedproperty @name=N'MS_DiagramPaneCount', @value=1 , @level0type=N'SCHEMA',@level0name=N'dbo', @level1type=N'VIEW',@level1name=N'vw_TransferOrderLines_Pending_ALL'
GO
EXEC sys.sp_addextendedproperty @name=N'MS_DiagramPane1', @value=N'[0E232FF0-B466-11cf-A24F-00AA00A3EFFF, 1.00]
Begin DesignProperties = 
   Begin PaneConfigurations = 
      Begin PaneConfiguration = 0
         NumPanes = 4
         Configuration = "(H (1[21] 4[40] 2[20] 3) )"
      End
      Begin PaneConfiguration = 1
         NumPanes = 3
         Configuration = "(H (1 [50] 4 [25] 3))"
      End
      Begin PaneConfiguration = 2
         NumPanes = 3
         Configuration = "(H (1 [50] 2 [25] 3))"
      End
      Begin PaneConfiguration = 3
         NumPanes = 3
         Configuration = "(H (4 [30] 2 [40] 3))"
      End
      Begin PaneConfiguration = 4
         NumPanes = 2
         Configuration = "(H (1 [56] 3))"
      End
      Begin PaneConfiguration = 5
         NumPanes = 2
         Configuration = "(H (2 [66] 3))"
      End
      Begin PaneConfiguration = 6
         NumPanes = 2
         Configuration = "(H (4 [50] 3))"
      End
      Begin PaneConfiguration = 7
         NumPanes = 1
         Configuration = "(V (3))"
      End
      Begin PaneConfiguration = 8
         NumPanes = 3
         Configuration = "(H (1[56] 4[18] 2) )"
      End
      Begin PaneConfiguration = 9
         NumPanes = 2
         Configuration = "(H (1 [75] 4))"
      End
      Begin PaneConfiguration = 10
         NumPanes = 2
         Configuration = "(H (1[66] 2) )"
      End
      Begin PaneConfiguration = 11
         NumPanes = 2
         Configuration = "(H (4 [60] 2))"
      End
      Begin PaneConfiguration = 12
         NumPanes = 1
         Configuration = "(H (1) )"
      End
      Begin PaneConfiguration = 13
         NumPanes = 1
         Configuration = "(V (4))"
      End
      Begin PaneConfiguration = 14
         NumPanes = 1
         Configuration = "(V (2))"
      End
      ActivePaneConfig = 0
   End
   Begin DiagramPane = 
      Begin Origin = 
         Top = 0
         Left = 0
      End
      Begin Tables = 
         Begin Table = "TransferOrderLines"
            Begin Extent = 
               Top = 6
               Left = 38
               Bottom = 136
               Right = 290
            End
            DisplayFlags = 280
            TopColumn = 12
         End
         Begin Table = "TransferOrderHeaders"
            Begin Extent = 
               Top = 7
               Left = 399
               Bottom = 137
               Right = 614
            End
            DisplayFlags = 280
            TopColumn = 4
         End
      End
   End
   Begin SQLPane = 
   End
   Begin DataPane = 
      Begin ParameterDefaults = ""
      End
      Begin ColumnWidths = 19
         Width = 284
         Width = 1500
         Width = 1500
         Width = 1500
         Width = 1500
         Width = 1500
         Width = 1500
         Width = 1500
         Width = 1500
         Width = 1500
         Width = 1500
         Width = 1500
         Width = 1500
         Width = 1500
         Width = 1500
         Width = 1500
         Width = 1500
         Width = 1500
         Width = 1500
      End
   End
   Begin CriteriaPane = 
      Begin ColumnWidths = 11
         Column = 2265
         Alias = 900
         Table = 1170
         Output = 720
         Append = 1400
         NewValue = 1170
         SortType = 1350
         SortOrder = 1410
         GroupBy = 1350
         Filter = 3480
         Or = 1350
         Or = 1350
         Or = 1350
      End
   End
End
' , @level0type=N'SCHEMA',@level0name=N'dbo', @level1type=N'VIEW',@level1name=N'vw_TransferOrderLines_Pending_InBR2WH_Transit'
GO
EXEC sys.sp_addextendedproperty @name=N'MS_DiagramPaneCount', @value=1 , @level0type=N'SCHEMA',@level0name=N'dbo', @level1type=N'VIEW',@level1name=N'vw_TransferOrderLines_Pending_InBR2WH_Transit'
GO
EXEC sys.sp_addextendedproperty @name=N'MS_DiagramPane1', @value=N'[0E232FF0-B466-11cf-A24F-00AA00A3EFFF, 1.00]
Begin DesignProperties = 
   Begin PaneConfigurations = 
      Begin PaneConfiguration = 0
         NumPanes = 4
         Configuration = "(H (1[40] 4[20] 2[20] 3) )"
      End
      Begin PaneConfiguration = 1
         NumPanes = 3
         Configuration = "(H (1 [50] 4 [25] 3))"
      End
      Begin PaneConfiguration = 2
         NumPanes = 3
         Configuration = "(H (1 [50] 2 [25] 3))"
      End
      Begin PaneConfiguration = 3
         NumPanes = 3
         Configuration = "(H (4 [30] 2 [40] 3))"
      End
      Begin PaneConfiguration = 4
         NumPanes = 2
         Configuration = "(H (1 [56] 3))"
      End
      Begin PaneConfiguration = 5
         NumPanes = 2
         Configuration = "(H (2 [66] 3))"
      End
      Begin PaneConfiguration = 6
         NumPanes = 2
         Configuration = "(H (4 [50] 3))"
      End
      Begin PaneConfiguration = 7
         NumPanes = 1
         Configuration = "(V (3))"
      End
      Begin PaneConfiguration = 8
         NumPanes = 3
         Configuration = "(H (1[56] 4[18] 2) )"
      End
      Begin PaneConfiguration = 9
         NumPanes = 2
         Configuration = "(H (1 [75] 4))"
      End
      Begin PaneConfiguration = 10
         NumPanes = 2
         Configuration = "(H (1[66] 2) )"
      End
      Begin PaneConfiguration = 11
         NumPanes = 2
         Configuration = "(H (4 [60] 2))"
      End
      Begin PaneConfiguration = 12
         NumPanes = 1
         Configuration = "(H (1) )"
      End
      Begin PaneConfiguration = 13
         NumPanes = 1
         Configuration = "(V (4))"
      End
      Begin PaneConfiguration = 14
         NumPanes = 1
         Configuration = "(V (2))"
      End
      ActivePaneConfig = 0
   End
   Begin DiagramPane = 
      Begin Origin = 
         Top = 0
         Left = 0
      End
      Begin Tables = 
         Begin Table = "TransferOrderLines"
            Begin Extent = 
               Top = 6
               Left = 38
               Bottom = 136
               Right = 290
            End
            DisplayFlags = 280
            TopColumn = 3
         End
         Begin Table = "TransferOrderHeaders"
            Begin Extent = 
               Top = 32
               Left = 411
               Bottom = 162
               Right = 626
            End
            DisplayFlags = 280
            TopColumn = 2
         End
         Begin Table = "Mx_Product_Master_new"
            Begin Extent = 
               Top = 160
               Left = 176
               Bottom = 296
               Right = 442
            End
            DisplayFlags = 280
            TopColumn = 3
         End
      End
   End
   Begin SQLPane = 
   End
   Begin DataPane = 
      Begin ParameterDefaults = ""
      End
      Begin ColumnWidths = 19
         Width = 284
         Width = 1500
         Width = 1500
         Width = 1500
         Width = 1500
         Width = 1500
         Width = 1500
         Width = 1500
         Width = 1500
         Width = 1500
         Width = 1500
         Width = 1500
         Width = 1500
         Width = 1500
         Width = 1500
         Width = 1500
         Width = 1500
         Width = 1500
         Width = 1500
      End
   End
   Begin CriteriaPane = 
      Begin ColumnWidths = 11
         Column = 1440
         Alias = 900
         Table = 1170
         Output = 720
         Append = 1400
         NewValue = 1170
         SortType = 1350
         SortOrder = 1410
         GroupBy = 1350
         Filter = 1350
         Or = 1350
         Or = 1350
         Or = 1350
     ' , @level0type=N'SCHEMA',@level0name=N'dbo', @level1type=N'VIEW',@level1name=N'vw_TransferOrderLines_Pending_WH'
GO
EXEC sys.sp_addextendedproperty @name=N'MS_DiagramPane2', @value=N' End
   End
End
' , @level0type=N'SCHEMA',@level0name=N'dbo', @level1type=N'VIEW',@level1name=N'vw_TransferOrderLines_Pending_WH'
GO
EXEC sys.sp_addextendedproperty @name=N'MS_DiagramPaneCount', @value=2 , @level0type=N'SCHEMA',@level0name=N'dbo', @level1type=N'VIEW',@level1name=N'vw_TransferOrderLines_Pending_WH'
GO
EXEC sys.sp_addextendedproperty @name=N'MS_DiagramPane1', @value=N'[0E232FF0-B466-11cf-A24F-00AA00A3EFFF, 1.00]
Begin DesignProperties = 
   Begin PaneConfigurations = 
      Begin PaneConfiguration = 0
         NumPanes = 4
         Configuration = "(H (1[40] 4[20] 2[20] 3) )"
      End
      Begin PaneConfiguration = 1
         NumPanes = 3
         Configuration = "(H (1 [50] 4 [25] 3))"
      End
      Begin PaneConfiguration = 2
         NumPanes = 3
         Configuration = "(H (1 [50] 2 [25] 3))"
      End
      Begin PaneConfiguration = 3
         NumPanes = 3
         Configuration = "(H (4 [30] 2 [40] 3))"
      End
      Begin PaneConfiguration = 4
         NumPanes = 2
         Configuration = "(H (1 [56] 3))"
      End
      Begin PaneConfiguration = 5
         NumPanes = 2
         Configuration = "(H (2 [66] 3))"
      End
      Begin PaneConfiguration = 6
         NumPanes = 2
         Configuration = "(H (4 [50] 3))"
      End
      Begin PaneConfiguration = 7
         NumPanes = 1
         Configuration = "(V (3))"
      End
      Begin PaneConfiguration = 8
         NumPanes = 3
         Configuration = "(H (1[56] 4[18] 2) )"
      End
      Begin PaneConfiguration = 9
         NumPanes = 2
         Configuration = "(H (1 [75] 4))"
      End
      Begin PaneConfiguration = 10
         NumPanes = 2
         Configuration = "(H (1[66] 2) )"
      End
      Begin PaneConfiguration = 11
         NumPanes = 2
         Configuration = "(H (4 [60] 2))"
      End
      Begin PaneConfiguration = 12
         NumPanes = 1
         Configuration = "(H (1) )"
      End
      Begin PaneConfiguration = 13
         NumPanes = 1
         Configuration = "(V (4))"
      End
      Begin PaneConfiguration = 14
         NumPanes = 1
         Configuration = "(V (2))"
      End
      ActivePaneConfig = 0
   End
   Begin DiagramPane = 
      Begin Origin = 
         Top = 0
         Left = 0
      End
      Begin Tables = 
         Begin Table = "TransferOrderLines_Upload_Raw"
            Begin Extent = 
               Top = 6
               Left = 38
               Bottom = 136
               Right = 208
            End
            DisplayFlags = 280
            TopColumn = 0
         End
         Begin Table = "Mx_Product_Master_new"
            Begin Extent = 
               Top = 177
               Left = 282
               Bottom = 307
               Right = 548
            End
            DisplayFlags = 280
            TopColumn = 3
         End
         Begin Table = "TransferOrderHeaders"
            Begin Extent = 
               Top = 0
               Left = 580
               Bottom = 218
               Right = 795
            End
            DisplayFlags = 280
            TopColumn = 0
         End
      End
   End
   Begin SQLPane = 
   End
   Begin DataPane = 
      Begin ParameterDefaults = ""
      End
      Begin ColumnWidths = 11
         Width = 284
         Width = 1500
         Width = 1500
         Width = 1500
         Width = 1500
         Width = 1500
         Width = 1500
         Width = 1500
         Width = 1500
         Width = 1500
         Width = 1500
      End
   End
   Begin CriteriaPane = 
      Begin ColumnWidths = 11
         Column = 3510
         Alias = 900
         Table = 1170
         Output = 720
         Append = 1400
         NewValue = 1170
         SortType = 1350
         SortOrder = 1410
         GroupBy = 1350
         Filter = 1350
         Or = 1350
         Or = 1350
         Or = 1350
      End
   End
End
' , @level0type=N'SCHEMA',@level0name=N'dbo', @level1type=N'VIEW',@level1name=N'vw_TransferOrderLines_Pending_WH_Upload'
GO
EXEC sys.sp_addextendedproperty @name=N'MS_DiagramPaneCount', @value=1 , @level0type=N'SCHEMA',@level0name=N'dbo', @level1type=N'VIEW',@level1name=N'vw_TransferOrderLines_Pending_WH_Upload'
GO
USE [master]
GO
ALTER DATABASE [MarinaDynamics365] SET  READ_WRITE 
GO
